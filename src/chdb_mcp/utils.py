"""Helpers for result truncation, SQL identifier safety, and SQL scanning."""

from __future__ import annotations

import re

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_TRUNCATION_NOTICE = (
    "\n\n[... result truncated at {limit} bytes; "
    "narrow the query or raise CHDB_MCP_MAX_RESULT_BYTES ...]"
)

# Table functions that reach outside the chDB process. When CHDB_MCP_FILE_ALLOWLIST
# is configured the user is signalling filesystem-isolation intent; any of these
# in a raw query() would bypass the allowlist (or, for url/s3/remote/db drivers,
# punch through to the network).
_EXTERNAL_SOURCE_FNS = (
    "file",
    "url",
    "urlWithHeaders",
    "s3",
    "s3Cluster",
    "remote",
    "remoteSecure",
    "cluster",
    "clusterAllReplicas",
    "hdfs",
    "hdfsCluster",
    "mongodb",
    "postgresql",
    "mysql",
    "redis",
    "sqlite",
    "odbc",
    "jdbc",
    "iceberg",
    "icebergS3",
    "icebergCluster",
    "deltaLake",
    "deltaLakeCluster",
    "azureBlobStorage",
    "azureBlobStorageCluster",
    "gcs",
)

# Match a function-call token: word boundary, name, optional whitespace, '('.
_EXTERNAL_SOURCE_RE = re.compile(
    r"\b(" + "|".join(_EXTERNAL_SOURCE_FNS) + r")\s*\(",
    re.IGNORECASE,
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


def find_external_source_calls(sql: str) -> list[str]:
    """Return the distinct external-source table functions invoked in `sql`.

    String literals and SQL comments are masked in a single left-to-right pass
    so that a string containing `/*` or `--` cannot smuggle a real function
    call past the scanner, and a comment containing `'` cannot mis-pair with
    later quotes to consume real SQL.
    """
    masked = _MASK_RE.sub(" ", sql)
    return sorted({m.group(1).lower() for m in _EXTERNAL_SOURCE_RE.finditer(masked)})
