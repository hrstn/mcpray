"""Module 7.3.3 / 7.3.4 — Tool-chaining executor ("chat → root").

`attack_graph` *finds* exploitation chains; this *executes* an ordered sequence
of MCP tool calls, capturing each hop's output (which feeds the next) and
producing a single chain Finding whose evidence is the full wire log — the
report-ready "from chat to root" trail.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..client import MCPClient
from ..findings import AbuseCategory, Finding, ScanResult, ServerInventory, Severity


class ChainExecutor:
    def __init__(self, client: MCPClient) -> None:
        self.client = client
        self.steps: list[dict] = []

    async def run(self, steps: list[dict], stop_on_fail: bool = False) -> list[dict]:
        """Execute ``steps`` = [{"tool": name, "arguments": {...}, "note"?: str}, ...]."""
        self.steps = []
        for idx, step in enumerate(steps, 1):
            tool = step.get("tool", "")
            args = step.get("arguments", {}) or {}
            result = await self.client.call_tool(tool, args)
            ok = bool(result.get("success"))
            rec = {
                "step": idx, "tool": tool, "arguments": args, "note": step.get("note", ""),
                "success": ok, "output": "\n".join(result.get("content", []) or []),
                "error": result.get("error"),
            }
            self.steps.append(rec)
            if not ok and stop_on_fail:
                break
        return self.steps

    def finding(self) -> Finding:
        ok = [s for s in self.steps if s["success"]]
        sev = Severity.CRITICAL if len(ok) >= 2 else (Severity.HIGH if ok else Severity.INFORMATIONAL)
        lines: list[str] = []
        for s in self.steps:
            status = "OK" if s["success"] else f"FAIL ({s['error']})"
            lines.append(f"[{s['step']}] {status}  call_tool({s['tool']}, {s['arguments']})")
            if s["output"]:
                lines.append(f"     → {s['output'][:400]}")
        return Finding(
            id="CHAIN-001",
            title=f"Tool Chain Executed — {len(ok)}/{len(self.steps)} hops (chat → root)",
            severity=sev,
            affected_component="MCP tool chain",
            evidence="Executed MCP tool-call chain:\n" + "\n".join(lines),
            reproduction_steps=[f"call_tool('{s['tool']}', {s['arguments']})" for s in self.steps],
            impact=("Chaining exposed MCP tools escalates a low-privilege foothold to full compromise: each "
                    "tool's output feeds the next, culminating in RCE / credential access / privilege escalation."),
            remediation=("Enforce per-tool authorization; never let one tool's output become trusted input to a "
                         "privileged tool. Segment high-impact tools behind separate credentials."),
            abuse_categories=[AbuseCategory.PRIVILEGE_ESCALATION, AbuseCategory.REMOTE_EXECUTION],
            risk_score=9.5 if sev == Severity.CRITICAL else (7.0 if ok else 1.0),
            tags=["tool-chaining", "mcp-7.3", "chat-to-root"],
        )

    def to_scan_result(self, target: str) -> ScanResult:
        """Wrap the chain as a ScanResult so it can be bundled with the wire log."""
        inv = ServerInventory(
            target=target, transport=self.client.transport, auth_required=self.client.auth_required,
            tools=[], resources=[], resource_templates=[], prompts=[],
        )
        f = self.finding()
        return ScanResult(
            target=target, scan_timestamp=datetime.now(timezone.utc).isoformat(), scanner_version="1.0.0",
            findings=[f], tool_abuse_factors=[], server_inventory=inv, attack_paths=[],
            overall_risk_score=f.risk_score, risk_level=f.severity, active_testing_enabled=True,
            wire_log=list(self.client.wire_log),
        )
