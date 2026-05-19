# chdb-mcp

[![PyPI](https://img.shields.io/pypi/v/chdb-mcp.svg)](https://pypi.org/project/chdb-mcp/)
[![CI](https://github.com/chdb-io/chdb-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/chdb-io/chdb-mcp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/chdb-mcp.svg)](https://pypi.org/project/chdb-mcp/)

An [MCP](https://modelcontextprotocol.io) server for [chDB](https://chdb.io), the in-process SQL OLAP engine powered by ClickHouse. Lets agents (Claude Desktop, Cursor, VS Code, Codex CLI, Cline, …) query Parquet, CSV, JSON, and pandas DataFrames with one tool — no separate server, no Docker.

## Why chdb-mcp?

- **Full ClickHouse engine, in-process.** 1000+ functions (`windowFunnel`, `quantilesTDigest`, `geoToH3`, the `-If`/`-State`/`-Merge` combinators), typed `JSON` with O(1) sub-column reads, native vectors, `MergeTree` storage.
- **Drop-in pandas API.** `import datastore as pd` covers ~300 pandas-shaped methods compiled to ClickHouse SQL. v1.0 adds `dataframe_query()` for zero-copy `Python(df)`.
- **~80 formats and 12+ source connectors in core.** Parquet, CSV, JSON, Avro, ORC, Arrow, Protobuf, plus `s3()`, `mongodb()`, `postgresql()`, `mysql()`, `iceberg()`, `deltaLake()` — no `INSTALL/LOAD` chain.
- **Federate to remote ClickHouse in one statement.** (v0.5) `remoteSecure('cluster:9440', 'db.table', ...)` joins local Parquet with a production ClickHouse cluster in one optimised plan.
- **Same SQL as your warehouse.** Copy-paste ClickHouse production queries into the agent prompt — no dialect bridge.

## Install

```bash
pip install chdb-mcp
```

## Connect

**Claude Desktop** — add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{ "mcpServers": { "chdb": { "command": "chdb-mcp" } } }
```

**Cursor / VS Code** — same JSON in `~/.cursor/mcp.json` etc.; one-click badges land in v0.2.

**Codex CLI / Claude Code / Copilot / Droid** — use the cross-IDE bundle [chdb-agent-plugin](https://github.com/chdb-io/chdb-agent-plugin).

## Tools (v0.1)

| Tool | Description |
|------|-------------|
| `query(sql, format)` | Run any read-only SQL on the in-process session |
| `list_databases()` | Enumerate visible databases |
| `list_tables(database)` | List tables in a database |
| `describe_table(database, table)` | Column types for a table |
| `query_file(path, sql, format)` | Query a Parquet/CSV/JSON file via the `{file}` placeholder |
| `get_sample_data(database, table, limit)` | First N rows of a table |
| `list_functions(pattern)` | List ClickHouse SQL functions (optional substring filter) |

Read-only by default — `SET readonly=2` blocks `INSERT`/`CREATE`/`DROP`/`ALTER` while keeping `file()`/`url()`/`s3()` usable. Set `CHDB_MCP_WRITE=1` to drop the guard. See [Security model](#security-model).

In `query_file`, `{file}` is replaced with `file('path', 'format')` before execution:

```python
query_file(
    path="/data/sales.parquet",
    sql="SELECT region, sum(revenue) FROM {file} GROUP BY region",
    format="Parquet",
)
```

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `CHDB_MCP_WRITE` | unset | If `1`, allows `INSERT`/`CREATE`/`DROP`/`ALTER` |
| `CHDB_MCP_MAX_RESULT_BYTES` | `1048576` | Per-tool result cap. Enforced engine-side (`max_result_bytes` + `result_overflow_mode='break'`) plus a final Python slice. |
| `CHDB_MCP_QUERY_TIMEOUT_SEC` | `30` | Wall-clock cap per query (chDB `max_execution_time`). `0` disables. |
| `CHDB_MCP_FILE_ALLOWLIST` | empty (unrestricted) | `:`-separated path prefixes. **Opt-in isolation switch** — when set, `query_file()` rejects paths outside the prefixes, and `query()` rejects external table functions (`file`/`url`/`s3`/`remote`/`hdfs`/`mongodb`/...). When unset, no filesystem gating happens — the host process is trusted. |
| `CHDB_MCP_SESSION_PATH` | empty | Persistent session directory (default: ephemeral) |

## Security model

chDB is **in-process**. There is no privilege boundary between the MCP server and the host Python interpreter, so the server can't make stronger isolation guarantees than the host already gives it. The model below reflects that.

### Trust tiers

1. **Default (no `CHDB_MCP_FILE_ALLOWLIST`)** — no filesystem gating. `query()` and `query_file()` can reach anything the host process can reach (any `file()`, `url()`, `s3()`, `remote()`...). Appropriate when the agent is trusted, or when the surrounding host application enforces the security boundary itself.
2. **Opt-in allowlist (`CHDB_MCP_FILE_ALLOWLIST=/data:/tmp/foo`)** — best-effort defense in depth:
   - `query_file()` rejects paths whose resolved (symlink-followed) form isn't under any listed prefix.
   - Both `query()` and `query_file()` reject SQL containing any table function that isn't on the safe-by-construction list (`numbers`/`values`/`view`/`merge`/`dictionary`/`generateRandom`/...). The "known" set is snapshotted from `system.table_functions` at session start, so the gate stays in sync with whatever the running chDB build actually exposes — including new external-source variants (`paimon*`, `prometheusQuery*`, `iceberg*Azure/S3/HDFS`), RCE-class functions (`executable`, `python`), and `*Cluster` siblings, without a hand-maintained denylist that goes stale.
   - For `query_file()`, the scan runs on the user SQL *before* the `{file}` placeholder substitution, so a `UNION ALL SELECT … FROM file('/etc/passwd', …)` smuggled into the query body is caught even though the explicit path is gated.
   - The scanner is comment- and string-aware (single-pass mask covering line comments, block comments, single-quoted strings with `''` / `\'` / `\\` escapes), and it normalizes backtick- and double-quote-wrapped identifiers (`` `file` `` / `"file"`) before matching so quoted function names can't bypass it.
   - This is **not a sandbox**: a determined caller can still try to exfiltrate via undiscovered functions, settings, or future chDB features. Strong enough for casual agent mistakes, not for adversarial input.
3. **Hard isolation** — for adversarial input, wrap the server in OS-level confinement: macOS App Sandbox, Linux user namespaces / seccomp, or Docker with a read-only filesystem mount. Nothing at the MCP layer can substitute for this.

### What's protected

- **Accidental writes** — `SET readonly=2` is applied at session start. `CHDB_MCP_WRITE=1` lifts it. (Note: ClickHouse's `readonly=2` still permits `TEMPORARY TABLE` writes and runtime `SET` changes — by design, not a bug.)
- **Runaway result sizes** — `CHDB_MCP_MAX_RESULT_BYTES` is enforced engine-side (`max_block_size` + `max_result_bytes` + `result_overflow_mode='break'`), not just as a post-hoc string slice. Large queries no longer materialize multi-MiB in chDB before truncation.
- **Runaway wall-clock** — `CHDB_MCP_QUERY_TIMEOUT_SEC` (default 30s) caps each query via chDB's `max_execution_time`.
- **SQL-identifier injection** — `list_tables` / `describe_table` / `get_sample_data` arguments are whitelist-regex'd (`[A-Za-z_][A-Za-z0-9_]*` only) and backtick-quoted before interpolation.
- **SQL string-literal escape** — `list_functions(pattern)` and `query_file(path, format)` arguments are passed through `quote_string`, which escapes both single quotes (`'` → `''`) and backslashes (`\` → `\\`) so that ClickHouse's `\'` escape form cannot break out of the literal.

### What's NOT protected

- **SQL audit.** Only the readonly guard — no allow/deny list of statements. Treat the agent as having full `SELECT` access to anything chDB can reach (subject to the allowlist when set).
- **Setting tampering.** Under `readonly=2`, the agent can still `SET max_memory_usage = …` to raise resource caps. Lock this down at the host or via OS-level resource limits if it matters.
- **Memory / CPU caps.** chDB's `max_memory_usage` applies, but there's no `ulimit`/`cgroups` equivalent imposed by the MCP layer.

For agents acting on untrusted input, run in a throwaway container.

## Roadmap

- **v0.5** — `query_remote_clickhouse()` federation tool
- **v1.0** — `attach_file()`, `dataframe_query()` (zero-copy `Python(df)`), HTTP/SSE transport with Bearer auth, `.mcpb` bundle for Claude Desktop one-click install

## Troubleshooting

### macOS: "Server disconnected" in Claude Desktop

If `~/Library/Logs/Claude/mcp-server-chdb.log` shows `PermissionError: Operation not permitted` on `pyvenv.cfg`, your venv sits under a TCC-protected directory (`~/Downloads`, `~/Documents`, `~/Desktop`) — Claude Desktop subprocesses can't read those paths.

Fix: install elsewhere. Recommended is `uvx` (zero-config, isolated under `~/.local/share/uv/`):

```json
{ "mcpServers": { "chdb": { "command": "uvx", "args": ["chdb-mcp"] } } }
```

Or build a venv yourself under `~/.local/share/chdb-mcp/.venv` and point Claude Desktop at its `chdb-mcp` binary.

### `query_file` returns "path is not under any prefix"

The allowlist resolves symlinks on both sides (so `/tmp` matches `/private/tmp` on macOS). If you still hit this, check the resolved form printed in the error against `python -c "from pathlib import Path; print(Path('YOUR_PATH').resolve())"`.

### "Cannot execute query in readonly mode"

`SET readonly=2` blocks DDL/DML by design. Rewrite as a pure `SELECT`, or restart with `CHDB_MCP_WRITE=1`.

### Per-server logs

```
~/Library/Logs/Claude/mcp-server-chdb.log   # startup diagnostics + stderr
~/Library/Logs/Claude/mcp.log                # all servers' JSON-RPC traffic
```

## Development

```bash
git clone https://github.com/chdb-io/chdb-mcp && cd chdb-mcp
pip install -e ".[dev]"
pytest && ruff check src tests
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
