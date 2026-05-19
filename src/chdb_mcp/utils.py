"""Helpers for result truncation, SQL identifier safety, and SQL scanning."""

from __future__ import annotations

import re

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_TRUNCATION_NOTICE = (
    "\n\n[... result truncated at {limit} bytes; "
    "narrow the query or raise CHDB_MCP_MAX_RESULT_BYTES ...]"
)

# Table functions that are safe by construction: they consume only literal /
# synthetic arguments and never reach outside the chDB process. Lowercase so
# matching against `system.table_functions` is case-insensitive. Anything in
# `system.table_functions` that is NOT in this set is treated as "potentially
# external" when CHDB_MCP_FILE_ALLOWLIST is configured.
#
# Note on `view`/`merge`/`dictionary`: these can *contain* nested table-function
# calls (e.g. `view(SELECT * FROM file(...))`), but the text-level scanner sees
# the inner `file(` directly, so allowlisting the wrappers is safe.
SAFE_TABLE_FUNCTIONS = frozenset(
    {
        "numbers",
        "numbers_mt",
        "zeros",
        "zeros_mt",
        "null",
        "values",
        "format",
        "input",
        "generaterandom",
        "generateseries",
        "generate_series",
        "primes",
        "loop",
        "fuzzquery",
        "fuzzjson",
        "view",
        "viewexplain",
        "viewifpermitted",
        "dictionary",
        "merge",
        "mergetreeindex",
        "mergetreeprojection",
        "mergetreeanalyzeindexes",
        "mergetreeanalyzeindexesuuid",
        "mergetreetextindex",
        "timeseriesdata",
        "timeseriesmetrics",
        "timeseriesselector",
        "timeseriestags",
    }
)

# Conservative fallback when `system.table_functions` can't be queried at
# session init (older chDB / build without it). Covers every table function
# that reaches outside the process on chDB 26.3, including the RCE-class
# `executable` and `python`. Kept lowercase to match the scanner.
FALLBACK_KNOWN_TABLE_FUNCTIONS = frozenset(
    {
        "file",
        "filecluster",
        "url",
        "urlcluster",
        "urlwithheaders",
        "s3",
        "s3cluster",
        "remote",
        "remotesecure",
        "cluster",
        "clusterallreplicas",
        "hdfs",
        "hdfscluster",
        "mongodb",
        "postgresql",
        "mysql",
        "redis",
        "sqlite",
        "odbc",
        "jdbc",
        "iceberg",
        "iceberglocal",
        "iceberglocalcluster",
        "icebergs3",
        "icebergs3cluster",
        "icebergazure",
        "icebergazurecluster",
        "iceberghdfs",
        "iceberghdfscluster",
        "deltalake",
        "deltalakelocal",
        "deltalakeazure",
        "deltalakeazurecluster",
        "deltalakes3",
        "deltalakes3cluster",
        "hudi",
        "hudicluster",
        "paimon",
        "paimonlocal",
        "paimonazure",
        "paimonazurecluster",
        "paimonhdfs",
        "paimonhdfscluster",
        "paimons3",
        "paimons3cluster",
        "paimoncluster",
        "azureblobstorage",
        "azureblobstoragecluster",
        "gcs",
        "cosn",
        "oss",
        "ytsaurus",
        "executable",
        "python",
        "prometheusquery",
        "prometheusqueryrange",
    }
)

# Single pass over the SQL: a token is either a string literal, a block
# comment, or a line comment. Left-to-right alternation guarantees that once
# a construct opens, its body is consumed up to the matching close before any
# other rule can fire — so `'/*' AS a, file(...), '*/' AS b` (where the user
# tries to smuggle a real call between two strings whose contents *look* like
# a block comment) cannot mislead the scanner.
#
# The string sub-pattern accepts all three escape forms ClickHouse honours:
# the SQL-standard `''` doubling, plus backslash escapes `\\'` and `\\\\` etc.
_MASK_RE = re.compile(
    r"'(?:[^'\\]|\\.|'')*'"  # single-quoted string with \. and '' escapes
    r"|--[^\n]*"  # line comment
    r"|/\*.*?\*/",  # block comment
    re.DOTALL,
)

# Backtick or double-quote wrapped identifier. Same quote required on both
# sides (backref) so mismatched quotes don't normalize, and the inner has to
# be a bare word (`\w+`) — chDB function names never contain quotes/dots.
_QUOTED_IDENT_RE = re.compile(r'(?P<q>[`"])(?P<name>\w+)(?P=q)')

# A function-call token: a word followed by optional whitespace and `(`.
_CALL_RE = re.compile(r"\b(\w+)\s*\(", re.IGNORECASE)


def truncate(payload: str, limit: int) -> str:
    """Trim `payload` to `limit` UTF-8 bytes; append a notice if cut."""
    encoded = payload.encode("utf-8")
    if len(encoded) <= limit:
        return payload
    return encoded[:limit].decode("utf-8", errors="ignore") + _TRUNCATION_NOTICE.format(limit=limit)


def quote_ident(name: str) -> str:
    """Backtick-quote a SQL identifier; reject anything needing escapes."""
    if not _IDENT_RE.match(name):
        raise ValueError(f"invalid SQL identifier: {name!r} (must match [A-Za-z_][A-Za-z0-9_]*)")
    return f"`{name}`"


def quote_string(value: str) -> str:
    """Single-quote a SQL string literal; escape backslashes and single quotes.

    ClickHouse string literals accept both SQL-standard `''` doubling AND
    backslash escapes (`\\'`, `\\\\`, `\\n` ...). So a value like ``x\\'`` could
    close the literal if we only doubled single quotes — the `\\'` would be
    parsed as an escaped quote and the following content as bare SQL. We escape
    backslashes first (otherwise the subsequent `'`→`''` step would be undone
    by `\\\\` → `\\'\\'` confusion), then double single quotes.
    """
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def find_disallowed_table_function_calls(sql: str, known: frozenset[str]) -> list[str]:
    """Return distinct table-function calls in `sql` that are not safe.

    Steps:
      1. Mask out string literals and SQL comments (single left-to-right pass
         so neither can smuggle the other).
      2. Normalize quoted identifiers: ``\\`file\\`(``  → ``file(``,
         ``\"file\"(`` → ``file(``. Without this, agents can bypass the scan
         by quoting the function name.
      3. Pick every ``word(`` token; flag any whose lowercase name is in
         ``known`` (the universe of table functions in the live chDB) but NOT
         in ``SAFE_TABLE_FUNCTIONS``. Scalar functions (``sum``, ``length``,
         ``concat`` etc.) aren't table functions so they aren't in ``known``
         and never flag — text-scanning is enough.

    The caller passes the dynamic ``known`` set (queried from
    ``system.table_functions`` at session start) so the gate stays in sync
    with whatever the running engine actually exposes — no hand-maintained
    denylist that goes stale when chDB adds ``paimon`` /
    ``prometheusQueryRange`` / ``iceberg…``.
    """
    masked = _MASK_RE.sub(" ", sql)
    normalized = _QUOTED_IDENT_RE.sub(r"\g<name>", masked)
    hits: set[str] = set()
    for m in _CALL_RE.finditer(normalized):
        name = m.group(1).lower()
        if name in known and name not in SAFE_TABLE_FUNCTIONS:
            hits.add(name)
    return sorted(hits)
