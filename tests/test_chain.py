"""Tool-chaining executor test (Module 7.3 — chat to root)."""
from mcpray.client import MCPClient
from mcpray.findings import Severity
from mcpray.reporters import bundle_reporter
from mcpray.scanners.chain_exec import ChainExecutor


class _Content:
    def __init__(self, text):
        self.text = text


class _ToolResult:
    def __init__(self, texts):
        self.content = [_Content(t) for t in texts]
        self.isError = False


class _FakeInner:
    """Two-hop mock: run_cmd leaks a path, read_file returns a private key."""
    async def call_tool(self, name, arguments):
        if name == "run_cmd":
            return _ToolResult(["uid=0(root)\n/root/.ssh/id_rsa"])
        if name == "read_file":
            return _ToolResult(["-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA...\n"])
        return _ToolResult(["unknown"])


async def test_chain_executes_and_bundles():
    client = MCPClient("http://target/mcp")
    client._client = _FakeInner()

    steps = [
        {"tool": "run_cmd", "arguments": {"cmd": "id; ls ~/.ssh"}},
        {"tool": "read_file", "arguments": {"path": "/root/.ssh/id_rsa"}},
    ]
    executor = ChainExecutor(client)
    executed = await executor.run(steps)

    assert len(executed) == 2
    assert all(s["success"] for s in executed)
    assert "uid=0(root)" in executed[0]["output"]
    assert "PRIVATE KEY" in executed[1]["output"]

    f = executor.finding()
    assert f.severity == Severity.CRITICAL  # 2 successful privesc hops
    assert "chat → root" in f.title

    result = executor.to_scan_result("http://target/mcp")
    assert len(result.wire_log) == 2  # both tool calls captured verbatim
    md = bundle_reporter.render(result)
    assert "id; ls ~/.ssh" in md          # request payload verbatim
    assert "BEGIN OPENSSH PRIVATE KEY" in md  # looted response verbatim
