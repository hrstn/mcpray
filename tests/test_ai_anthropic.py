"""Anthropic provider in the AI layer — correct Messages-API request + parsing."""
import json as _json

from mcpray.ai.client import AIClient
from mcpray.findings import AbuseCategory, Finding, Severity


class _Resp:
    def __init__(self, data):
        self._d = data
        self.status_code = 200
        self.text = _json.dumps(data)

    def raise_for_status(self):
        pass

    def json(self):
        return self._d


class _FakeClient:
    captured: dict = {}

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None):
        _FakeClient.captured = {"url": url, "headers": headers, "json": json}
        return _Resp({
            "content": [{"type": "text", "text": '{"verification":"confirmed","confidence":0.9,"reasoning":"rce"}'}],
            "stop_reason": "end_turn",
        })


def _finding():
    return Finding(
        id="F1", title="Command Injection", severity=Severity.CRITICAL,
        affected_component="tool:run_cmd", evidence="e", reproduction_steps=["s"],
        impact="i", remediation="r", abuse_categories=[AbuseCategory.REMOTE_EXECUTION],
    )


async def test_anthropic_request_shape_and_parse(monkeypatch):
    monkeypatch.setattr("mcpray.ai.client.httpx.AsyncClient", _FakeClient)
    client = AIClient(mode="anthropic", anthropic_api_key="sk-ant-test")
    result = await client.analyze_finding(_finding())

    cap = _FakeClient.captured
    assert cap["url"].endswith("/v1/messages")
    assert cap["headers"]["x-api-key"] == "sk-ant-test"
    assert cap["headers"]["anthropic-version"] == "2023-06-01"
    assert cap["json"]["model"] == "claude-opus-4-8"
    assert cap["json"]["max_tokens"] == 1024
    assert "temperature" not in cap["json"]  # current Claude models reject it (400)

    assert result["_provider"] == "anthropic"
    assert result["confidence"] == 0.9
    assert result["verification"] == "confirmed"


def test_anthropic_key_from_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")
    assert AIClient(mode="anthropic").anthropic_api_key == "sk-from-env"
