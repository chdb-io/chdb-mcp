"""End-to-end stdio smoke test: spawn `chdb-mcp` and drive it as a real MCP client.

Resolves the binary in this order so the script is portable across dev / CI:
  1. ``CHDB_MCP_BIN`` env var (explicit override)
  2. ``shutil.which("chdb-mcp")`` (binary on PATH)
  3. Bare ``chdb-mcp`` (delegate to the spawning shell's resolution)
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _resolve_chdb_mcp_bin() -> str:
    return os.environ.get("CHDB_MCP_BIN") or shutil.which("chdb-mcp") or "chdb-mcp"


async def main() -> None:
    server = StdioServerParameters(command=_resolve_chdb_mcp_bin(), env=None)
    async with (
        stdio_client(server) as (read, write),
        ClientSession(read, write) as session,
    ):
        init = await session.initialize()
        print(
            f"[handshake] server={init.serverInfo.name} "
            f"v{init.serverInfo.version} protocol={init.protocolVersion}"
        )

        tools = await session.list_tools()
        tool_names = [t.name for t in tools.tools]
        print(f"[tools/list] {tool_names}")
        assert set(tool_names) == {
            "query",
            "list_databases",
            "list_tables",
            "describe_table",
            "query_file",
            "get_sample_data",
            "list_functions",
        }, f"unexpected tool set: {tool_names}"

        # v0.1.1: handshake must report the chdb-mcp package, not the SDK.
        assert init.serverInfo.name == "chdb-mcp", init.serverInfo.name
        assert init.serverInfo.version, "missing serverInfo.version"
        # v0.1.1: we register no resources/prompts, so caps should be None.
        assert init.capabilities.prompts is None
        assert init.capabilities.resources is None

        r = await session.call_tool("query", {"sql": "SELECT 1 AS x, 'hi' AS y"})
        text = r.content[0].text
        print(f"[query] {text!r}")
        assert "1" in text and "hi" in text

        r = await session.call_tool("list_databases", {})
        text = r.content[0].text
        print(f"[list_databases] {text!r}")
        assert "system" in text

        r = await session.call_tool("describe_table", {"database": "system", "table": "one"})
        text = r.content[0].text
        print(f"[describe_table system.one] {text!r}")
        assert "dummy" in text

        r = await session.call_tool(
            "get_sample_data", {"database": "system", "table": "numbers", "limit": 3}
        )
        text = r.content[0].text
        print(f"[get_sample_data system.numbers limit=3] {text!r}")

        # query_file with a real CSV
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as fh:
            fh.write("a,b\n1,one\n2,two\n3,three\n4,four\n")
            csv_path = fh.name
        try:
            r = await session.call_tool(
                "query_file",
                {
                    "path": csv_path,
                    "sql": "SELECT count() AS n, sum(a) AS total FROM {file}",
                    "format": "CSVWithNames",
                },
            )
            text = r.content[0].text
            print(f"[query_file count+sum] {text!r}")
            assert "4" in text and "10" in text
        finally:
            Path(csv_path).unlink()

        # readonly guard
        r = await session.call_tool(
            "query", {"sql": "CREATE TABLE default.x (a Int32) ENGINE=Memory"}
        )
        print(f"[write attempt] isError={r.isError}, text={r.content[0].text!r}")
        assert r.isError, "readonly guard must reject DDL"
        assert "readonly" in r.content[0].text.lower()

        # identifier injection
        r = await session.call_tool("list_tables", {"database": "foo; DROP TABLE bar"})
        print(f"[injection attempt] isError={r.isError}, text={r.content[0].text!r}")
        assert r.isError

    print("\n[OK] all stdio smoke-test assertions passed.")


if __name__ == "__main__":
    asyncio.run(main())
