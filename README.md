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
| `CHDB_MCP_MAX_RESULT_BYTES` | `1048576` | Per-tool result truncation threshold |
| `CHDB_MCP_FILE_ALLOWLIST` | empty | `:`-separated path prefixes for `query_file()`; symlinks resolved on both sides. **Advisory** — see [Security model](#security-model). |
| `CHDB_MCP_SESSION_PATH` | empty | Persistent session directory (default: ephemeral) |

## Security model

**Protects against**: accidental writes (`readonly=2`), runaway result sizes (per-tool truncation), SQL-identifier injection in `list_tables` / `describe_table` / `get_sample_data` arguments (whitelist regex + escaping).

**Does NOT protect against**:

- **Filesystem reach.** `CHDB_MCP_FILE_ALLOWLIST` only guards `query_file()`; the `query()` tool accepts arbitrary SQL, and chDB exposes `file()` / `url()` / `s3()` / `remote()` directly. A determined caller bypasses the allowlist. Use OS-level isolation (macOS App Sandbox, Linux namespaces, Docker with a read-only mount) for real sandboxing.
- **SQL audit.** Only the readonly guard — no allow/deny list of statements. Treat the agent as having full `SELECT` access to anything chDB can reach.
- **Resource limits.** No memory / CPU / wall-clock caps in v0.1. Use `ulimit` / `cgroups` if needed.

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
