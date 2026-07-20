"""Report-bundle exporter — MCP scan results as exam-report-ready Markdown.

Findings tagged with MITRE ATLAS + OWASP-LLM ids, plus a **verbatim wire
transcript** appendix (every MCP request/response captured on the client), so
the operator can satisfy the OSAI "include all your queries as text" rule.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..findings import ScanResult
from . import atlas_owasp


def _fence(text: str | None) -> str:
    return "```\n" + (text if text is not None else "") + "\n```"


def _cat_values(finding) -> list[str]:
    return [c.value if hasattr(c, "value") else str(c) for c in finding.abuse_categories]


def render(result: ScanResult) -> str:
    inv = result.server_inventory
    L: list[str] = [
        "# mcpray — MCP Security Report Bundle",
        "",
        f"- **Target:** {result.target}",
        f"- **Scanned:** {result.scan_timestamp} · mcpray {result.scanner_version}",
        f"- **Overall risk:** {result.risk_level.value} ({result.overall_risk_score:.1f}/10) · "
        f"findings: {len(result.findings)} · active testing: {result.active_testing_enabled}",
        f"- **Transport:** {inv.transport} · **Auth required:** {inv.auth_required} · "
        f"tools={len(inv.tools)} resources={len(inv.resources)} templates={len(inv.resource_templates)} prompts={len(inv.prompts)}",
        "",
        "## Findings",
        "",
    ]
    if not result.findings:
        L.append("_No findings._")
    for f in result.findings:
        L.append(f"### [{f.severity.value}] {f.title}")
        tags = atlas_owasp.tag_line(_cat_values(f))
        if tags:
            L.append(tags)
        L.append("")
        L.append(f"- **Component:** `{f.affected_component}`")
        if f.tags:
            L.append(f"- **Tags:** {', '.join(f.tags)}")
        L += ["", "**Evidence:**", _fence(f.evidence)]
        if f.reproduction_steps:
            L.append("**Reproduction:**")
            L += [f"{i}. {s}" for i, s in enumerate(f.reproduction_steps, 1)]
        L += [f"**Impact:** {f.impact}", f"**Remediation:** {f.remediation}", ""]

    if result.attack_paths:
        L += ["## Attack paths", ""]
        for p in result.attack_paths:
            L.append(f"### {p.name} ({p.likelihood})")
            L += [f"- {s}" for s in p.steps]
            L += [f"_Impact: {p.impact}_", ""]

    wl = getattr(result, "wire_log", []) or []
    L += ["## Appendix — Wire Transcript (verbatim evidence)", ""]
    if not wl:
        L.append("_No wire log captured for this run._")
    for i, e in enumerate(wl, 1):
        latency = f" ({e.get('latency_ms')}ms)" if e.get("latency_ms") is not None else ""
        L.append(f"### {i}. {e.get('op')} → {e.get('target')}{latency}")
        L += ["**Request:**", _fence(json.dumps(e.get("params", {}), indent=2, default=str))]
        if e.get("error"):
            L.append(f"**Error:** {e['error']}")
        else:
            L += ["**Response (verbatim):**", _fence(str(e.get("response", "")))]
        L.append("")
    return "\n".join(L)


def write(result: ScanResult, output_path: str) -> None:
    Path(output_path).write_text(render(result), encoding="utf-8")
