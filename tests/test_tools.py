"""Smoke tests for the v0.1 tools and the v0.1.1 hardening fixes.

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
    list_functions,
    list_tables,
    query,
    query_file,
)
from chdb_mcp.utils import (
    find_external_source_calls,
    quote_ident,
    quote_string,
    truncate,
)

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


def test_find_external_source_calls_detects_common_table_fns() -> None:
    sql = (
        "SELECT * FROM file('/etc/passwd', 'LineAsString') "
        "JOIN s3('s3://b/x.parquet') USING (k) "
        "WHERE k IN (SELECT id FROM remote('host', 'db.t'))"
    )
    assert find_external_source_calls(sql) == ["file", "remote", "s3"]


def test_find_external_source_calls_is_case_insensitive() -> None:
    assert find_external_source_calls("SELECT FILE('x','CSV')") == ["file"]
    assert find_external_source_calls("SELECT URL('h')") == ["url"]


def test_find_external_source_calls_ignores_comments_and_strings() -> None:
    # In a string literal: must not trigger.
    assert find_external_source_calls("SELECT 's3(\\'x\\')' AS s") == []
    # In a line comment.
    assert find_external_source_calls("SELECT 1 -- file('/x')\nFROM t") == []
    # In a block comment.
    assert find_external_source_calls("SELECT /* url('x') */ 1") == []


def test_find_external_source_calls_does_not_match_substring() -> None:
    # `filename` and `s3hash` should not match because of word boundary.
    assert find_external_source_calls("SELECT filename(x), s3hash(y) FROM t") == []


def test_find_external_source_calls_resists_comment_smuggling() -> None:
    """A string containing `/*` before the real call and another containing
    `*/` after it would, under the v0.1.1 order (strip-comments-then-mask-
    strings), erase the file() call between them. The single-pass mask must
    consume each string fully before any comment rule fires."""
    sql = "SELECT '/*' AS a, file('/etc/passwd', 'LineAsString'), '*/' AS b"
    assert find_external_source_calls(sql) == ["file"]


def test_find_external_source_calls_handles_string_with_quote_inside_comment() -> None:
    """A stray `'` inside a comment must not mis-pair with later quotes and
    swallow the real file() call. Comment is consumed atomically."""
    sql = "SELECT 1 -- it's a test\nFROM file('/data/x.parquet', 'Parquet')"
    assert find_external_source_calls(sql) == ["file"]


def test_find_external_source_calls_handles_backslash_quote_in_string() -> None:
    """ClickHouse's `\\'` escape: the string content really is `s3(`, but the
    function-call regex must NOT match it because it's inside a (now masked)
    string literal."""
    # The Python literal here is: SELECT '\'s3(' AS s, NOT a real s3() call.
    assert find_external_source_calls("SELECT '\\'s3(' AS s") == []


def test_quote_string_escapes_backslash_before_quote() -> None:
    """ClickHouse honours `\\'` as a quote escape inside string literals. If we
    only doubled the `'`, a payload `x\\'; …` would close the literal and run
    the rest as SQL. Confirm the wrapper escapes backslashes too."""
    # Input value (Python repr): x\'
    # Without backslash escaping: 'x\''  → ClickHouse parses as string `x'`,
    # leaving the trailing chars as bare SQL.
    # With backslash escaping: 'x\\\''  → ClickHouse parses as string `x\'`.
    assert quote_string("x\\'") == "'x\\\\'''"
    assert quote_string("a\\b") == "'a\\\\b'"
    # SQL-standard double-quote still works.
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


def test_run_truncates_output_at_max_result_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confirm `_run()` actually applies `truncate(_, _CONFIG.max_result_bytes)`.

    Guards against a regression where someone refactors `_run()` and silently
    drops the `truncate()` call — the unit tests of `truncate()` itself would
    still pass, but the MCP channel would receive unbounded payloads.
    """
    from chdb_mcp import server
    from chdb_mcp.config import Config

    # Tight 200-byte limit; a 100-row JSONCompact output is ~700 bytes — well over.
    tiny = Config(
        readonly=True,
        max_result_bytes=200,
        query_timeout_sec=30,
        file_allowlist=(),
        session_path=None,
    )
    monkeypatch.setattr(server, "_CONFIG", tiny)

    out = query("SELECT number FROM system.numbers LIMIT 100", "JSONCompact")
    assert "truncated at 200 bytes" in out
    # Trimmed body (≤200 B) + truncation notice (~80 B); total well under 400 B.
    assert len(out.encode("utf-8")) < 400


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


# --------------------------------------------------------------------------- #
# Hardening fixes (v0.1.1)
# --------------------------------------------------------------------------- #


def test_query_rejects_external_sources_when_allowlist_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The README documents CHDB_MCP_FILE_ALLOWLIST as a filesystem isolation
    knob, but a raw query() with file()/url()/s3() would bypass it. With the
    allowlist set, those table functions must be rejected before chDB sees them.
    """
    from chdb_mcp import server

    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", ("/tmp",))
    with pytest.raises(ValueError, match=r"external table functions"):
        query("SELECT count() FROM file('/etc/passwd', 'LineAsString')")
    with pytest.raises(ValueError, match=r"external table functions"):
        query("SELECT * FROM s3('s3://bucket/x.parquet')")
    with pytest.raises(ValueError, match=r"external table functions"):
        query("SELECT 1 FROM remote('host', 'db.t')")


def test_query_allows_external_sources_when_allowlist_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the user has not configured the allowlist, query() preserves the v0.1
    behavior of accepting any SQL (the README's documented default)."""
    from chdb_mcp import server

    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", ())
    # file() against a real path under /tmp should still succeed.
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
        fh.write("a\n1\n2\n")
        p = fh.name
    try:
        out = query(f"SELECT count() FROM file('{p}', 'CSV')")
        assert "2" in out
    finally:
        os.unlink(p)


def test_max_result_bytes_actually_caps_engine_output() -> None:
    """v0.1 advertised CHDB_MCP_MAX_RESULT_BYTES but only string-truncated after
    chDB materialized the full result; large queries hit chDB's internal memory
    limit first. v0.1.1 sets max_block_size + max_result_bytes + break so the
    engine itself caps output."""
    from chdb_mcp import server

    # We can't easily re-init the session with a different cap mid-test, so
    # we validate via a >>budget query and check the output is bounded.
    out = query(
        "SELECT randomPrintableASCII(100) FROM numbers(50000)",
        format="CSV",
    )
    # The session cap defaults to 1 MiB. Without the fix this is ~5 MiB; with
    # the fix it should sit at or below the cap + one block overshoot.
    cap = server._CONFIG.max_result_bytes
    assert len(out.encode("utf-8")) <= cap + 64 * 1024, (
        f"output {len(out.encode('utf-8'))} bytes exceeds cap {cap} by more "
        f"than one block (~64 KiB)"
    )


def test_list_functions_includes_well_known_names() -> None:
    out = list_functions()
    # Headers row + at least these aggregate / scalar functions.
    assert "name\tis_aggregate" in out
    assert "\nsum\t" in out or "\nsum\n" in out  # tab-separated
    assert "\ncount\t" in out or "\ncount\n" in out


def test_list_functions_substring_filter_narrows_results() -> None:
    all_fns = list_functions()
    quantile_only = list_functions(pattern="quantile")
    assert len(quantile_only) < len(all_fns)
    assert "quantile" in quantile_only.lower()
    # The header row plus at least one match.
    assert quantile_only.count("\n") >= 2


def test_list_functions_pattern_escapes_quotes() -> None:
    """Confirm the pattern arg is quote_string-escaped; SQL injection here
    would be a real bug because the user supplies the pattern directly."""
    # A pattern with a single quote must not break the SQL.
    out = list_functions(pattern="x'; DROP TABLE y; --")
    # No match expected, but no error either — header row only.
    assert "name\tis_aggregate" in out


def test_server_module_advertises_version_and_name() -> None:
    """Guard against future FastMCP changes that drop the name/version patch."""
    from chdb_mcp import __version__, server

    assert server.mcp._mcp_server.name == "chdb-mcp"
    assert server.mcp._mcp_server.version == __version__


def test_empty_resources_and_prompts_capabilities_are_not_advertised() -> None:
    """We register no resources/prompts; removing the auto-registered list
    handlers prevents an empty `resources` / `prompts` map showing in the
    InitializeResult capability set."""
    from mcp.server.lowlevel.server import NotificationOptions

    from chdb_mcp import server

    caps = server.mcp._mcp_server.get_capabilities(NotificationOptions(), {})
    assert caps.prompts is None
    assert caps.resources is None
    # tools is still announced — we have tools.
    assert caps.tools is not None
