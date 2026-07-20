"""stdio transport (Module 8.1.1) + protocol preflight — end-to-end against a
real local fastmcp stdio server."""
from mcpray.preflight import preflight
from mcpray.scanner import run_scan

_SERVER = '''from fastmcp import FastMCP

mcp = FastMCP("test-stdio")


@mcp.tool
def echo(text: str) -> str:
    """Echo the provided text back to the caller."""
    return text


if __name__ == "__main__":
    mcp.run()
'''


async def test_stdio_scan(tmp_path):
    path = tmp_path / "srv.py"
    path.write_text(_SERVER)
    result = await run_scan(str(path))
    assert result.server_inventory.transport == "STDIO"
    assert any(t["name"] == "echo" for t in result.server_inventory.tools)


async def test_preflight_reports_protocol(tmp_path):
    path = tmp_path / "srv.py"
    path.write_text(_SERVER)
    info = await preflight(str(path))
    assert info["reachable"] is True
    assert info["transport"] == "STDIO"
    assert info["fastmcp_version"]
    assert info["protocol_version"]  # negotiated during the stdio handshake
