"""chDB MCP Server — registers six read-only tools by default.

Layout: a single `server.py` owns the FastMCP instance and registers each tool
as a top-level function. Heavy lifting (truncation, identifier quoting) lives
in `utils.py`; env-driven settings in `config.py`.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from mcp.server.fastmcp import FastMCP

from chdb_mcp.config import Config
from chdb_mcp.utils import quote_ident, quote_string, truncate

if TYPE_CHECKING:
    from chdb.session import Session

log = logging.getLogger("chdb_mcp")

_CONFIG: Config = Config.from_env()
_SESSION: Session | None = None

# Resolve allowlist prefixes once so symlinks normalize the same way as
# user-supplied paths. On macOS this matters: /tmp is a symlink to /private/tmp,
# so a prefix "/tmp" must compare against the resolved "/private/tmp/...".
_RESOLVED_ALLOWLIST: tuple[str, ...] = tuple(
    str(Path(p).expanduser().resolve()) for p in _CONFIG.file_allowlist
)


def _get_session() -> Session:
    """Lazily open the chDB session; apply readonly guard once."""
    global _SESSION
    if _SESSION is not None:
        return _SESSION

    from chdb import session as chdb_session

    _SESSION = (
        chdb_session.Session(_CONFIG.session_path)
        if _CONFIG.session_path
        else chdb_session.Session()
    )
    if _CONFIG.readonly:
        # readonly=2 refuses INSERT/CREATE/DROP/ALTER but still allows SET and
        # table functions like file()/url()/s3()/remote() — which we need for
        # query_file(). readonly=1 is too strict (blocks file()).
        _SESSION.query("SET readonly=2")
    return _SESSION


def _run(sql: str, fmt: str = "JSONCompact") -> str:
    """Execute SQL and return a truncated string payload."""
    sess = _get_session()
    result = sess.query(sql, fmt)
    # chdb's result object exposes a few possible accessors across versions;
    # str(result) is the most portable and yields the formatted output.
    payload = str(result)
    return truncate(payload, _CONFIG.max_result_bytes)


def _check_path(path: str) -> None:
    """Reject paths outside CHDB_MCP_FILE_ALLOWLIST (if configured).

    Both the input path and the configured prefixes are symlink-resolved before
    comparison; a `/` separator is appended to each prefix so "/tmp" does not
    accidentally match a sibling like "/tmp_evil". This is advisory — the
    `query` tool can still reach `file()` directly and bypass it.
    """
    if not _RESOLVED_ALLOWLIST:
        return
    resolved = str(Path(path).expanduser().resolve())
    if not any(
        resolved == prefix or resolved.startswith(prefix.rstrip("/") + "/")
        for prefix in _RESOLVED_ALLOWLIST
    ):
        raise ValueError(
            f"path {path!r} (resolved to {resolved!r}) is not under any prefix "
            f"in CHDB_MCP_FILE_ALLOWLIST; allowed prefixes: "
            f"{list(_RESOLVED_ALLOWLIST)}"
        )


mcp = FastMCP(
    name="chdb",
    instructions=(
        "Run SQL against the in-process chDB engine. Tools cover ad-hoc queries, "
        "schema introspection, and querying local files (Parquet/CSV/JSON) via the "
        "file() table function. Read-only by default. ClickHouse SQL dialect."
    ),
)


@mcp.tool()
def query(sql: str, format: str = "JSONCompact") -> str:
    """Execute an arbitrary SQL statement against the chDB session.

    Use ClickHouse SQL dialect. Common formats: ``JSONCompact`` (default),
    ``CSVWithNames``, ``TabSeparatedWithNames``, ``Pretty``. The result is
    truncated at ``CHDB_MCP_MAX_RESULT_BYTES`` (default 1 MiB).

    Args:
        sql: Any read-only SQL (SELECT/SHOW/DESCRIBE/EXPLAIN). Writes require
            ``CHDB_MCP_WRITE=1``.
        format: Output format passed to chDB. Defaults to ``JSONCompact``.
    """
    log.info("query: %.200s", sql)
    return _run(sql, format)


@mcp.tool()
def list_databases() -> str:
    """List databases visible to the chDB session.

    Returns one database name per line (TabSeparated format).
    """
    return _run("SHOW DATABASES", "TabSeparated")


@mcp.tool()
def list_tables(database: str) -> str:
    """List tables in a given database.

    Args:
        database: Database name. Must be a plain SQL identifier
            (letters, digits, underscore — no quotes, dots, or spaces).
    """
    return _run(f"SHOW TABLES FROM {quote_ident(database)}", "TabSeparated")


@mcp.tool()
def describe_table(database: str, table: str) -> str:
    """Return column types for a table.

    Args:
        database: Database name (plain identifier).
        table: Table name (plain identifier).
    """
    return _run(
        f"DESCRIBE TABLE {quote_ident(database)}.{quote_ident(table)}",
        "TabSeparatedWithNames",
    )


@mcp.tool()
def query_file(path: str, sql: str, format: str = "Parquet") -> str:
    """Query a local file (Parquet/CSV/JSON/…) as if it were a table.

    The literal token ``{file}`` in ``sql`` is substituted with a
    ``file('path', 'format')`` table-function call before execution.

    Example::

        query_file(
            path="/data/sales.parquet",
            sql="SELECT region, sum(revenue) FROM {file} GROUP BY region",
            format="Parquet",
        )

    Args:
        path: Filesystem path. If ``CHDB_MCP_FILE_ALLOWLIST`` is set, the
            resolved path must sit under one of its prefixes.
        sql: Query body. Must contain the literal placeholder ``{file}``.
        format: chDB file format hint. Common values: ``Parquet``, ``CSV``,
            ``CSVWithNames``, ``JSONEachRow``, ``Arrow``.
    """
    _check_path(path)
    if "{file}" not in sql:
        raise ValueError("sql must contain the literal placeholder '{file}'")
    file_expr = f"file({quote_string(path)}, {quote_string(format)})"
    rendered_sql = sql.replace("{file}", file_expr)
    return _run(rendered_sql)


@mcp.tool()
def get_sample_data(database: str, table: str, limit: int = 10) -> str:
    """Return the first N rows of a table.

    Args:
        database: Database name (plain identifier).
        table: Table name (plain identifier).
        limit: Maximum rows. Clamped to ``[1, 1000]``.
    """
    n = max(1, min(int(limit), 1000))
    return _run(f"SELECT * FROM {quote_ident(database)}.{quote_ident(table)} LIMIT {n}")


def main() -> None:
    """Run the server on stdio (the default transport for desktop MCP clients)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log.info(
        "chdb-mcp starting (readonly=%s, max_bytes=%s, session=%s, allowlist=%s)",
        _CONFIG.readonly,
        _CONFIG.max_result_bytes,
        _CONFIG.session_path or "<ephemeral>",
        list(_CONFIG.file_allowlist) or "<unrestricted>",
    )
    mcp.run(transport="stdio")
