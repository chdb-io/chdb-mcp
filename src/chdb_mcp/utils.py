"""Helpers for result truncation and SQL identifier safety."""

from __future__ import annotations

import re

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_TRUNCATION_NOTICE = (
    "\n\n[... result truncated at {limit} bytes; "
    "narrow the query or raise CHDB_MCP_MAX_RESULT_BYTES ...]"
)


def truncate(payload: str, limit: int) -> str:
    """Trim `payload` to `limit` UTF-8 bytes; append a notice if cut."""
    encoded = payload.encode("utf-8")
    if len(encoded) <= limit:
        return payload
    return encoded[:limit].decode("utf-8", errors="ignore") + _TRUNCATION_NOTICE.format(
        limit=limit
    )


def quote_ident(name: str) -> str:
    """Backtick-quote a SQL identifier; reject anything needing escapes."""
    if not _IDENT_RE.match(name):
        raise ValueError(
            f"invalid SQL identifier: {name!r} "
            "(must match [A-Za-z_][A-Za-z0-9_]*)"
        )
    return f"`{name}`"


def quote_string(value: str) -> str:
    """Single-quote a SQL string literal, doubling embedded quotes."""
    return "'" + value.replace("'", "''") + "'"
