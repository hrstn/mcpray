"""A2A session, agent-card + OpenAPI discovery, and topology classification.

OSAI Module 4.1 (architecture / coordination patterns / frameworks) and 4.2
(enumerating A2A workflows: agent-card discovery, OpenAPI endpoint extraction).
Every HTTP op is recorded in a ``wire_log`` (same shape as ``MCPClient``) so A2A
findings bundle with verbatim evidence.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ..findings import Finding, ScanResult, ServerInventory, Severity

_WELL_KNOWN = [
    "/.well-known/agent.json",
    "/.well-known/agent-card.json",
    "/.well-known/ai-plugin.json",
]
_REGISTRY_PATHS = ["/agents", "/a2a/agents", "/.well-known/agents.json", "/api/agents"]
_OPENAPI_PATHS = ["/openapi.json", "/.well-known/openapi.json", "/api/openapi.json", "/swagger.json"]

_FRAMEWORKS = {
    "langgraph": "LangGraph", "langchain": "LangChain", "autogen": "AutoGen (Microsoft)",
    "crewai": "CrewAI", "crew": "CrewAI", "swarm": "OpenAI Swarm",
    "a2a": "Google A2A protocol", "semantic-kernel": "Semantic Kernel",
}


@dataclass
class AgentCard:
    name: str
    description: str
    url: str
    version: str
    skills: list[dict]
    capabilities: dict
    provider: dict
    source_url: str
    raw: dict


@dataclass
class A2AEndpoint:
    path: str
    method: str
    summary: str
    params: list[str]


@dataclass
class A2ADiscoveryResult:
    base_url: str
    reachable: bool
    cards: list[AgentCard]
    registry_agents: list[dict]  # [{name, url}]
    registry_url: str | None
    endpoints: list[A2AEndpoint]
    openapi_url: str | None
    notes: list[str]
    wire_log: list[dict]


class A2ASession:
    def __init__(self, timeout: float = 15.0, headers: dict | None = None,
                 proxy: str | None = None, verify: bool = False):
        self.wire_log: list[dict] = []
        kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(timeout, connect=8.0), "verify": verify,
            "follow_redirects": True, "headers": headers or {},
        }
        if proxy:
            try:
                self._client = httpx.AsyncClient(proxy=proxy, **kwargs)
            except TypeError:
                self._client = httpx.AsyncClient(proxies=proxy, **kwargs)
        else:
            self._client = httpx.AsyncClient(**kwargs)

    async def __aenter__(self) -> "A2ASession":
        return self

    async def __aexit__(self, *a) -> None:
        await self._client.aclose()

    def _log(self, op, url, params, ok, response, error=None, latency_ms=None):
        self.wire_log.append({
            "ts": datetime.now(timezone.utc).isoformat(), "op": op, "target": url,
            "params": params, "ok": ok,
            "response": response if isinstance(response, str) else str(response),
            "error": error, "latency_ms": latency_ms,
        })

    async def get(self, url: str) -> httpx.Response | None:
        start = time.monotonic()
        try:
            r = await self._client.get(url)
            self._log("GET", url, {}, True, r.text[:20000], latency_ms=int((time.monotonic() - start) * 1000))
            return r
        except Exception as e:
            self._log("GET", url, {}, False, "", error=str(e), latency_ms=int((time.monotonic() - start) * 1000))
            return None

    async def post(self, url: str, json_body: Any = None) -> httpx.Response | None:
        start = time.monotonic()
        try:
            r = await self._client.post(url, json=json_body)
            self._log("POST", url, {"body": json_body}, True, r.text[:20000],
                      latency_ms=int((time.monotonic() - start) * 1000))
            return r
        except Exception as e:
            self._log("POST", url, {"body": json_body}, False, "", error=str(e),
                      latency_ms=int((time.monotonic() - start) * 1000))
            return None


def _parse_card(data: dict, source_url: str) -> AgentCard:
    return AgentCard(
        name=str(data.get("name", "")), description=str(data.get("description", "")),
        url=str(data.get("url", "")), version=str(data.get("version", "")),
        skills=data.get("skills") or data.get("tools") or [],
        capabilities=data.get("capabilities") or {}, provider=data.get("provider") or {},
        source_url=source_url, raw=data,
    )


async def discover(session: A2ASession, base_url: str) -> A2ADiscoveryResult:
    base_url = base_url.rstrip("/")
    if not urlparse(base_url).scheme:
        base_url = "http://" + base_url
    notes: list[str] = []
    cards: list[AgentCard] = []
    reachable = False

    # Agent cards (.well-known)
    for path in _WELL_KNOWN:
        r = await session.get(urljoin(base_url + "/", path.lstrip("/")))
        if r is None:
            continue
        reachable = True
        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, dict) and (data.get("name") or data.get("url") or data.get("skills")):
                    cards.append(_parse_card(data, path))
            except Exception:
                pass
    if not cards:
        notes.append("No agent card at /.well-known/agent.json — target may not be A2A, or uses a custom path.")

    # Registry (list of agents)
    registry_agents: list[dict] = []
    registry_url: str | None = None
    for path in _REGISTRY_PATHS:
        r = await session.get(base_url + path)
        if r is None or r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        items = data if isinstance(data, list) else (data.get("agents") if isinstance(data, dict) else None)
        if isinstance(items, list) and items:
            registry_url = base_url + path
            for it in items:
                if isinstance(it, dict):
                    registry_agents.append({"name": it.get("name", ""), "url": it.get("url", "")})
                elif isinstance(it, str):
                    registry_agents.append({"name": it, "url": ""})
            break

    # OpenAPI endpoints
    endpoints: list[A2AEndpoint] = []
    openapi_url: str | None = None
    for path in _OPENAPI_PATHS:
        r = await session.get(base_url + path)
        if r is None or r.status_code != 200:
            continue
        try:
            spec = r.json()
        except Exception:
            continue
        if isinstance(spec, dict) and "paths" in spec:
            openapi_url = base_url + path
            for p, methods in (spec.get("paths") or {}).items():
                for method, op in (methods or {}).items():
                    if not isinstance(op, dict):
                        continue
                    params = [pr.get("name", "") for pr in (op.get("parameters") or []) if isinstance(pr, dict)]
                    endpoints.append(A2AEndpoint(path=p, method=method.upper(),
                                                 summary=str(op.get("summary", ""))[:120], params=params))
            break

    return A2ADiscoveryResult(
        base_url=base_url, reachable=reachable, cards=cards, registry_agents=registry_agents,
        registry_url=registry_url, endpoints=endpoints, openapi_url=openapi_url,
        notes=notes, wire_log=session.wire_log,
    )


def classify(result: A2ADiscoveryResult) -> dict:
    """Infer system type, coordination pattern (4.1.2), and framework (4.1.3)."""
    n_agents = len(result.registry_agents) + max(0, len(result.cards) - 1)
    haystack = " ".join([
        *(c.name + " " + c.description + " " + c.url for c in result.cards),
        *(str(s) for c in result.cards for s in c.skills),
        *(a.get("name", "") + " " + a.get("url", "") for a in result.registry_agents),
        *(e.path + " " + e.summary for e in result.endpoints),
    ]).lower()

    framework = next((v for k, v in _FRAMEWORKS.items() if k in haystack), None)
    signals: list[str] = []

    multi = bool(result.registry_agents) or len(result.cards) > 1 or n_agents >= 1 and bool(result.registry_url)
    system_type = "multi_agent" if (result.registry_agents or len(result.cards) > 1) else (
        "single_agent" if result.cards else "unknown")

    coordination = "unknown"
    if system_type == "multi_agent":
        if any(k in haystack for k in ("orchestrat", "coordinator", "hub", "dispatch", "router", "supervisor-agent")):
            coordination = "orchestrator"; signals.append("central orchestrator/coordinator signal")
        elif any(k in haystack for k in ("pipeline", "chain", "stage", "step", "workflow")):
            coordination = "pipeline"; signals.append("sequential pipeline/chain signal")
        elif any(k in haystack for k in ("supervisor", "hierarch", "manager", "worker")):
            coordination = "hierarchical"; signals.append("supervisor/worker hierarchy signal")
        elif any(k in haystack for k in ("peer", "mesh", "gossip")):
            coordination = "peer_to_peer"; signals.append("peer-to-peer/mesh signal")
    elif system_type == "single_agent":
        coordination = "none"

    return {
        "system_type": system_type, "coordination_pattern": coordination,
        "framework": framework, "agent_count": len(result.registry_agents) or len(result.cards),
        "signals": signals,
    }


def build_scan_result(target: str, findings: list[Finding], wire_log: list[dict]) -> ScanResult:
    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFORMATIONAL: 4}
    top = min((f.severity for f in findings), key=lambda s: sev_order[s], default=Severity.INFORMATIONAL)
    inv = ServerInventory(target=target, transport="A2A/HTTP", auth_required=False,
                          tools=[], resources=[], resource_templates=[], prompts=[])
    return ScanResult(
        target=target, scan_timestamp=datetime.now(timezone.utc).isoformat(), scanner_version="1.0.0",
        findings=findings, tool_abuse_factors=[], server_inventory=inv, attack_paths=[],
        overall_risk_score=max((f.risk_score for f in findings), default=0.0),
        risk_level=top, active_testing_enabled=True, wire_log=wire_log,
    )
