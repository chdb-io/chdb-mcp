"""chDB MCP Server — registers six read-only tools by default.

Layout: a single `server.py` owns the FastMCP instance and registers each tool
as a top-level function. Heavy lifting (truncation, identifier quoting, SQL
source-function scanning) lives in `utils.py`; env-driven settings in `config.py`.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

from mcp.server.fastmcp import FastMCP

from chdb_mcp import __version__
from chdb_mcp.config import Config
from chdb_mcp.utils import (
    find_external_source_calls,
    quote_ident,
    quote_string,
    truncate,
)

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
    """Lazily open the chDB session; apply readonly + resource caps once."""
    global _SESSION
    if _SESSION is not None:
        return _SESSION

    from chdb import session as chdb_session

    _SESSION = (
        chdb_session.Session(_CONFIG.session_path)
        if _CONFIG.session_path
        else chdb_session.Session()
    )

    # Cap engine work BEFORE flipping readonly=2, in case a future chDB release
    # tightens which settings stay writable under readonly. Order is defensive.
    #
    # max_block_size is shrunk because result_overflow_mode='break' only checks
    # between blocks; at the default 65505 rows/block, a single block can swamp
    # max_result_bytes before break ever fires. With block_size=8192 the engine
    # overshoots the byte budget by at most one block, and the post-hoc Python
    # truncate() trims the final overshoot precisely.
    setup_sql_parts = [
        "max_block_size = 8192",
        f"max_result_bytes = {_CONFIG.max_result_bytes}",
        "result_overflow_mode = 'break'",
    ]
    if _CONFIG.query_timeout_sec > 0:
        # max_execution_time aborts queries past N wall-clock seconds at the
        # engine level — agent-driven runaways can't hang the stdio loop.
        setup_sql_parts.append(f"max_execution_time = {_CONFIG.query_timeout_sec}")
    _SESSION.query("SET " + ", ".join(setup_sql_parts))

    if _CONFIG.readonly:
        # readonly=2 refuses INSERT/CREATE/DROP/ALTER on persistent tables but
        # still allows SET and table functions like file()/url()/s3()/remote()
        # — which we need for query_file(). readonly=1 is too strict.
        _SESSION.query("SET readonly=2")
    return _SESSION


def _run(sql: str, fmt: str = "JSONCompact", tool: str = "query") -> str:
    """Execute SQL and return a truncated string payload, with timing logged."""
    sess = _get_session()
    started = time.monotonic()
    try:
        result = sess.query(sql, fmt)
    except Exception as e:
        elapsed_ms = (time.monotonic() - started) * 1000
        log.info(
            "tool=%s fmt=%s elapsed_ms=%.1f status=error err=%s sql=%.200s",
            tool,
            fmt,
            elapsed_ms,
            type(e).__name__,
            sql,
        )
        raise
    # chdb's result object exposes a few possible accessors across versions;
    # str(result) is the most portable and yields the formatted output.
    payload = str(result)
    truncated = truncate(payload, _CONFIG.max_result_bytes)
    elapsed_ms = (time.monotonic() - started) * 1000
    log.info(
        "tool=%s fmt=%s elapsed_ms=%.1f bytes=%d truncated=%s sql=%.200s",
        tool,
        fmt,
        elapsed_ms,
        len(truncated.encode("utf-8")),
        truncated is not payload,
        sql,
    )
    return truncated


def _check_path(path: str) -> None:
    """Reject paths outside CHDB_MCP_FILE_ALLOWLIST (if configured).

    Both the input path and the configured prefixes are symlink-resolved before
    comparison; a `/` separator is appended to each prefix so "/tmp" does not
    accidentally match a sibling like "/tmp_evil".
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


def _reject_external_sources_if_allowlist_set(sql: str) -> None:
    """When allowlist is configured, raw query() must not reach external sources.

    Without this guard, an agent could trivially bypass the allowlist via
    ``SELECT * FROM file('/etc/passwd', 'LineAsString')`` — making the allowlist
    a false-comfort feature. With allowlist set, route file access through
    query_file() (which path-checks); for s3/url/remote/etc., unset the allowlist.
    """
    if not _RESOLVED_ALLOWLIST:
        return
    hits = find_external_source_calls(sql)
    if hits:
        raise ValueError(
            f"query() refuses external table functions {hits} while "
            f"CHDB_MCP_FILE_ALLOWLIST is set; use query_file() for files, "
            f"or unset the allowlist to allow url/s3/remote/etc."
        )


mcp = FastMCP(
    name="chdb-mcp",
    instructions=(
        "Run SQL against the in-process chDB engine. Tools cover ad-hoc queries, "
        "schema introspection, and querying local files (Parquet/CSV/JSON) via the "
        "file() table function. Read-only by default. ClickHouse SQL dialect."
    ),
)
# FastMCP doesn't forward `version` to the lowlevel Server, so the InitializeResult
# would otherwise report the mcp SDK version. Patch it through directly.
mcp._mcp_server.version = __version__
# We register no resources or prompts; drop the auto-registered list_resources /
# list_prompts handlers so the capability map doesn't advertise empty menus.
try:
    from mcp.types import (
        ListPromptsRequest,
        ListResourcesRequest,
        ListResourceTemplatesRequest,
    )

    for _req in (ListPromptsRequest, ListResourcesRequest, ListResourceTemplatesRequest):
        mcp._mcp_server.request_handlers.pop(_req, None)
except ImportError:  # pragma: no cover — future-proof against mcp internal moves
    pass


@mcp.tool()
def query(sql: str, format: str = "JSONCompact") -> str:
    """Execute an arbitrary SQL statement against the chDB session.

    Use ClickHouse SQL dialect. Common formats: ``JSONCompact`` (default),
    ``CSVWithNames``, ``TabSeparatedWithNames``, ``Pretty``. The result is
    truncated at ``CHDB_MCP_MAX_RESULT_BYTES`` (default 1 MiB) and the query
    is aborted after ``CHDB_MCP_QUERY_TIMEOUT_SEC`` seconds (default 30).

    Args:
        sql: Any read-only SQL (SELECT/SHOW/DESCRIBE/EXPLAIN). Writes require
            ``CHDB_MCP_WRITE=1``. When ``CHDB_MCP_FILE_ALLOWLIST`` is set,
            external table functions (file/url/s3/remote/...) are rejected
            here; use ``query_file()`` for files instead.
        format: Output format passed to chDB. Defaults to ``JSONCompact``.
    """
    _reject_external_sources_if_allowlist_set(sql)
    return _run(sql, format, tool="query")


@mcp.tool()
def list_databases() -> str:
    """List databases visible to the chDB session.

    Returns one database name per line (TabSeparated format).
    """
    return _run("SHOW DATABASES", "TabSeparated", tool="list_databases")


@mcp.tool()
def list_tables(database: str) -> str:
    """List tables in a given database.

    Args:
        database: Database name. Must be a plain SQL identifier
            (letters, digits, underscore — no quotes, dots, or spaces).
    """
    return _run(
        f"SHOW TABLES FROM {quote_ident(database)}",
        "TabSeparated",
        tool="list_tables",
    )


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
        tool="describe_table",
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
    return _run(rendered_sql, tool="query_file")


@mcp.tool()
def get_sample_data(database: str, table: str, limit: int = 10) -> str:
    """Return the first N rows of a table.

    Args:
        database: Database name (plain identifier).
        table: Table name (plain identifier).
        limit: Maximum rows. Clamped to ``[1, 1000]``.
    """
    n = max(1, min(int(limit), 1000))
    return _run(
        f"SELECT * FROM {quote_ident(database)}.{quote_ident(table)} LIMIT {n}",
        tool="get_sample_data",
    )


@mcp.tool()
def list_functions(pattern: str | None = None) -> str:
    """List SQL functions available in the chDB engine.

    Returns ``name``, ``is_aggregate``, ``case_insensitive``, ``alias_to`` for
    each entry in ``system.functions`` — useful for agents discovering
    ClickHouse's 1000+ function library (``windowFunnel``, ``quantilesTDigest``,
    ``-If``/``-State``/``-Merge`` combinators, etc.) in one round trip.

    Args:
        pattern: Optional case-insensitive substring filter on the function
            name. Plain text only; SQL wildcards and quotes are escaped.
    """
    sql = "SELECT name, is_aggregate, case_insensitive, alias_to FROM system.functions"
    if pattern:
        sql += f" WHERE positionCaseInsensitive(name, {quote_string(pattern)}) > 0"
    sql += " ORDER BY name"
    return _run(sql, "TabSeparatedWithNames", tool="list_functions")


def main() -> None:
    """Run the server on stdio (the default transport for desktop MCP clients)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log.info(
        "chdb-mcp v%s starting (readonly=%s, max_bytes=%s, timeout_sec=%s, "
        "session=%s, allowlist=%s)",
        __version__,
        _CONFIG.readonly,
        _CONFIG.max_result_bytes,
        _CONFIG.query_timeout_sec,
        _CONFIG.session_path or "<ephemeral>",
        list(_CONFIG.file_allowlist) or "<unrestricted>",
    )
    mcp.run(transport="stdio")
