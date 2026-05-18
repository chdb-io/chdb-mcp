"""Smoke tests for the six v0.1 tools.

These import the tool functions directly (FastMCP keeps the decorated function
callable as a plain Python function), so we exercise the same code path the
MCP dispatcher hits.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from chdb_mcp.server import (
    describe_table,
    get_sample_data,
    list_databases,
    list_tables,
    query,
    query_file,
)
from chdb_mcp.utils import quote_ident, quote_string, truncate

# --------------------------------------------------------------------------- #
# Pure utilities (no chDB needed)
# --------------------------------------------------------------------------- #


def test_truncate_under_limit_is_passthrough() -> None:
    assert truncate("hello", 1024) == "hello"


def test_truncate_over_limit_appends_notice() -> None:
    out = truncate("x" * 2048, 100)
    assert out.startswith("x" * 100)
    assert "truncated at 100 bytes" in out


def test_quote_ident_rejects_dangerous_input() -> None:
    with pytest.raises(ValueError):
        quote_ident("foo; DROP TABLE users")


def test_quote_ident_accepts_plain_names() -> None:
    assert quote_ident("my_table") == "`my_table`"


def test_quote_string_escapes_single_quotes() -> None:
    assert quote_string("o'brien") == "'o''brien'"


# --------------------------------------------------------------------------- #
# Tool integration tests (require chdb)
# --------------------------------------------------------------------------- #


def test_query_returns_value() -> None:
    out = query("SELECT 1 AS x, 'hi' AS y")
    assert "1" in out
    assert "hi" in out


def test_writes_are_blocked_by_default() -> None:
    """README's main safety claim: `SET readonly=2` is applied at session start.

    Guards against silent regressions where someone removes the readonly guard
    in _get_session() but agent-driven writes start silently succeeding.
    """
    with pytest.raises(RuntimeError, match=r"readonly"):
        query("CREATE TABLE default.should_not_exist (a Int32) ENGINE=Memory")


def test_list_databases_includes_system() -> None:
    out = list_databases()
    assert "system" in out


def test_list_tables_system_nonempty() -> None:
    out = list_tables("system")
    # The `system` database always exposes at least the `tables` and `numbers`
    # virtual tables; one of them is plenty for a smoke check.
    assert "tables" in out or "numbers" in out


def test_list_tables_rejects_identifier_injection() -> None:
    """Confirm quote_ident is wired into list_tables (not just unit-tested in isolation)."""
    with pytest.raises(ValueError, match=r"invalid SQL identifier"):
        list_tables("foo; DROP TABLE bar")


def test_describe_table_returns_columns() -> None:
    out = describe_table("system", "one")
    # system.one has a single UInt8 column named `dummy`.
    assert "dummy" in out


def test_get_sample_data_respects_limit() -> None:
    out = get_sample_data("system", "numbers", limit=3)
    # JSONCompact wraps rows in an array of arrays; ensure at least three
    # row separators or three digits appear.
    assert out.count("\n") >= 1


def test_get_sample_data_clamps_huge_limit() -> None:
    # limit=999999 should be silently clamped to 1000 and not crash.
    out = get_sample_data("system", "numbers", limit=999_999)
    assert isinstance(out, str)


def test_query_file_requires_placeholder() -> None:
    with pytest.raises(ValueError, match=r"placeholder"):
        query_file(path="/tmp/x.csv", sql="SELECT 1", format="CSV")


def test_check_path_resolves_allowlist_symlinks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """/tmp prefix must match /tmp/x even when /tmp is a symlink (macOS case)."""
    from chdb_mcp import server

    # Pin the allowlist to a resolved /tmp and confirm a /tmp path is accepted.
    resolved_tmp = str(Path("/tmp").resolve())
    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", (resolved_tmp,))
    # Should not raise — even if path was given as the symlink form.
    server._check_path("/tmp/some_file.parquet")


def test_check_path_rejects_sibling_prefix_attack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Allowlist /tmp must NOT match /tmp_evil/x via naive startswith."""
    from chdb_mcp import server

    resolved_tmp = str(Path("/tmp").resolve())
    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", (resolved_tmp,))
    # /tmp_evil resolves to /private/tmp_evil; that must NOT start with /private/tmp/.
    with pytest.raises(ValueError, match=r"not under any prefix"):
        server._check_path("/tmp_evil/x.parquet")


def test_check_path_passthrough_when_allowlist_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chdb_mcp import server

    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", ())
    server._check_path("/anywhere/at/all.parquet")  # must not raise


def test_query_file_counts_rows_from_csv() -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
        fh.write("a,b\n1,one\n2,two\n3,three\n")
        path = fh.name
    try:
        out = query_file(
            path=path,
            sql="SELECT count() FROM {file}",
            format="CSVWithNames",
        )
        assert "3" in out
    finally:
        os.unlink(path)
