"""A2A / multi-agent tests (Module 4) against a mock A2A platform."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from mcpray.a2a.attacks import data_poison, rogue_register, workflow_probe
from mcpray.a2a.core import A2ASession, classify, discover
from mcpray.findings import Severity

_AGENTS = [
    {"name": "scanner-agent", "url": "http://a/scan"},
    {"name": "reporter-agent", "url": "http://a/report"},
]
_STORE = {"content": ""}

_CARD = {
    "name": "Sales Orchestrator", "version": "1.0",
    "description": "Central orchestrator that dispatches tasks to sub-agents.",
    "url": "http://target/a2a",
    "skills": [{"id": "orchestrate", "name": "orchestrate", "description": "route + dispatch to workers"}],
    "capabilities": {"streaming": True},
    "provider": {"organization": "MegaCorp"},
}
_OPENAPI = {"openapi": "3.0.0", "paths": {"/task": {"post": {"summary": "run a task",
            "parameters": [{"name": "input", "in": "query"}]}}}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/.well-known/agent.json":
            return self._send(200, _CARD)
        if p == "/openapi.json":
            return self._send(200, _OPENAPI)
        if p == "/agents":
            return self._send(200, _AGENTS)
        return self._send(404, {"error": "nf"})

    def do_POST(self):
        p = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if p == "/agents":
            _AGENTS.append({"name": body.get("name", ""), "url": body.get("url", "")})
            return self._send(201, {"registered": True})
        if p == "/store":
            _STORE["content"] = str(body.get("content", ""))
            return self._send(200, {"ok": True})
        if p == "/chat":
            return self._send(200, {"answer": f"Latest notes: {_STORE['content']}"})
        if p == "/task":
            inp = str(body.get("input", ""))
            if "xp_cmdshell" in inp:
                return self._send(200, {"error": "SQL syntax error near xp_cmdshell"})
            return self._send(200, {"report": f"Task done. Content: {inp}"})
        return self._send(404, {"error": "nf"})


def _serve():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


async def test_discovery_and_classification():
    srv, port = _serve()
    base = f"http://127.0.0.1:{port}"
    try:
        async with A2ASession() as s:
            result = await discover(s, base)
            c = classify(result)
    finally:
        srv.shutdown()
    assert result.reachable
    assert any(card.name == "Sales Orchestrator" for card in result.cards)
    assert len(result.registry_agents) >= 2
    assert any(e.path == "/task" and e.method == "POST" for e in result.endpoints)
    assert c["system_type"] == "multi_agent"
    assert c["coordination_pattern"] == "orchestrator"


async def test_rogue_registration():
    srv, port = _serve()
    base = f"http://127.0.0.1:{port}"
    before = len(_AGENTS)
    try:
        async with A2ASession() as s:
            finding = await rogue_register(s, f"{base}/agents", name="evil-agent")
    finally:
        srv.shutdown()
    assert len(_AGENTS) == before + 1
    assert finding.severity == Severity.CRITICAL     # verified in listing
    assert "CONFIRMED" in finding.title


async def test_data_poison_and_workflow():
    srv, port = _serve()
    base = f"http://127.0.0.1:{port}"
    try:
        async with A2ASession() as s:
            poison = await data_poison(s, f"{base}/store", "content", f"{base}/chat", "query")
            wf = await workflow_probe(s, f"{base}/task")
    finally:
        srv.shutdown()
    # canary planted then echoed back by the downstream agent
    assert poison.severity == Severity.CRITICAL
    assert "CONFIRMED" in poison.title
    # workflow: link reflected + xp_cmdshell surfaced
    titles = " ".join(f.title for f in wf)
    assert "Output Manipulation" in titles
    assert "xp_cmdshell" in titles
