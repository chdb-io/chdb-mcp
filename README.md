# chdb-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for [chDB](https://github.com/chdb-io/chdb) — the in-process OLAP SQL engine powered by ClickHouse.

`chdb-mcp` lets Claude, Cursor, ChatGPT, and any MCP-compatible client run analytical SQL over local files, federate to ClickHouse Cloud clusters, and operate on pandas / Polars DataFrames — all without standing up a database server.

> Status: pre-launch placeholder. The initial release is coming soon. See [Roadmap](#roadmap) for the planned tool surface.

## What this is

chDB embeds the ClickHouse query engine as a library. `chdb-mcp` wraps it in the MCP protocol so that:

- An LLM agent can run arbitrary SQL against Parquet, CSV, JSON, or S3 sources with no setup.
- The same agent can `JOIN` local data with a remote ClickHouse Cloud cluster via `remoteSecure()` in a single query.
- DataFrames already in the agent's memory are queryable as tables through `Python(df)`.

The server is read-only by default, with result truncation, and supports both `stdio` (Claude Desktop, Cursor, Claude Code) and HTTP/SSE (Bearer auth, `/health` endpoint) transports.

## Install

```bash
pip install chdb-mcp
```

Or run without installation:

```bash
uvx chdb-mcp
```

### Claude Desktop

Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "chdb": {
      "command": "uvx",
      "args": ["chdb-mcp"]
    }
  }
}
```

A `.mcpb` one-click bundle will be published alongside v0.1.

### Cursor / VS Code

A one-click install deeplink will be available in v0.1.

## Planned tool surface

### v0.1 — read-only core

| Tool | Description |
|---|---|
| `query` | Execute a SQL statement; result truncated to a configurable row cap. |
| `list_databases` | List databases visible to the current session. |
| `list_tables` | List tables in the current or specified database. |
| `describe_table` | Return column names, types, and sample values for a table. |
| `query_file` | Run a query against a local Parquet / CSV / JSON file. |
| `get_sample_data` | Return N sample rows from a table or file. |

### v1.0 — chDB differentiators

| Tool | Description |
|---|---|
| `attach_file` | Register a file as a queryable table for the rest of the session. |
| `query_remote_clickhouse` | Federate a query to a remote ClickHouse cluster via `remoteSecure()`. |
| `dataframe_query` | Query a DataFrame already in scope using the `Python(df)` table function. |

## Roadmap

- **v0.1** — six read-only tools, PyPI release, stdio transport, registration with the [official MCP Registry](https://registry.modelcontextprotocol.io), Smithery, mcp.so, Glama, PulseMCP, and MCP.directory.
- **v1.0** — three differentiating tools (`attach_file`, `query_remote_clickhouse`, `dataframe_query`), HTTP/SSE transport with Bearer auth, `.mcpb` bundle for Claude Desktop, "Add to Cursor" deeplink, VS Code one-click button.
- **Hosted Remote MCP** — `mcp.chdb.io` with OAuth, multi-tenant isolation, and S3-only mode for ClickHouse Cloud customers. Tracked separately.

Milestones land incrementally; check back here or follow [@chdb_io](https://twitter.com/chdb_io) for releases.

## Configuration

The server reads environment variables for default behavior:

| Variable | Default | Purpose |
|---|---|---|
| `CHDB_DATA_DIR` | `~/.chdb` | Persistent session storage location. |
| `CHDB_READ_ONLY` | `true` | Reject DDL / DML statements when set. |
| `CHDB_MAX_ROWS` | `1000` | Hard cap on rows returned per query. |
| `CHDB_BEARER_TOKEN` | — | If set, HTTP transport requires this token. |

## Security

`chdb-mcp` runs in-process — there is no network listener unless you explicitly enable HTTP/SSE transport. When HTTP is enabled, Bearer authentication is required and `/health` is the only public endpoint.

Read-only mode (`CHDB_READ_ONLY=true`, the default) rejects `INSERT`, `CREATE`, `DROP`, and `ALTER`. For workflows that need write access, set `CHDB_READ_ONLY=false` and confine the data directory via `CHDB_DATA_DIR`.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Related

- Main chDB repository: https://github.com/chdb-io/chdb
- chDB documentation: https://clickhouse.com/docs/chdb
- LLM-friendly index: https://clickhouse.com/docs/chdb/llms.txt
- Model Context Protocol: https://modelcontextprotocol.io
- Companion server for ClickHouse cluster admin: https://github.com/ClickHouse/mcp-clickhouse
- Community: https://discord.gg/D2Daa2fM5K
