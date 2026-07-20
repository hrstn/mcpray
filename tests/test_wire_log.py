"""Wire-log capture test — MCPClient records every operation verbatim."""
from mcpray.client import MCPClient


class _Content:
    def __init__(self, text):
        self.text = text


class _ResourceResult:
    def __init__(self, text):
        self.contents = [_Content(text)]


class _ToolResult:
    def __init__(self, texts):
        self.content = [_Content(t) for t in texts]
        self.isError = False


class _FakeInner:
    async def read_resource(self, uri):
        return _ResourceResult(f"value-for::{uri}")

    async def call_tool(self, name, arguments):
        return _ToolResult([f"ran {name} with {arguments}"])


async def test_wire_log_captures_operations():
    client = MCPClient("http://target/mcp")
    client._client = _FakeInner()  # bypass real connect

    text = await client.read_resource("price://100")
    assert text == "value-for::price://100"

    result = await client.call_tool("run_cmd", {"cmd": "whoami"})
    assert result["success"] is True

    log = client.wire_log
    assert len(log) == 2

    rr = log[0]
    assert rr["op"] == "read_resource" and rr["params"]["uri"] == "price://100"
    assert "value-for::price://100" in rr["response"]

    ct = log[1]
    assert ct["op"] == "call_tool"
    assert ct["params"]["arguments"] == {"cmd": "whoami"}
    assert "ran run_cmd" in ct["response"]
    assert rr["latency_ms"] is not None
