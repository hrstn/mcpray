"""Module 7.2 — Tool Description Poisoning + MCP-Apps UI Poisoning/Spoofing.

A consuming AI client reads MCP tool/prompt descriptions (and rendered tool
output) as *trusted context*. This scanner flags metadata that embeds
instructions targeting that client: injected imperatives, hidden/obfuscated
characters, embedded tool-call/exfil directives, and spoofed UI chrome.
"""
from __future__ import annotations

import re

from ..findings import AbuseCategory, Finding, Severity, ServerInventory
from .base import BaseScanner

# Zero-width joiners/spaces + BOM/word-joiner; and bidirectional/RTL overrides.
_ZERO_WIDTH = "​‌‍﻿⁠"
_BIDI = "‪‫‬‭‮"

_ZERO_WIDTH = "".join(chr(c) for c in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060))
_BIDI = "".join(chr(c) for c in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E))

# (regex, label, severity) — injected instructions aimed at the consuming LLM.
_INJECTION = [
    (re.compile(r"ignore\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|context|messages?)", re.I), "instruction override", Severity.HIGH),
    (re.compile(r"disregard\s+(the\s+|your\s+|all\s+)?(above|previous|prior|earlier)", re.I), "instruction override", Severity.HIGH),
    (re.compile(r"\byou\s+are\s+now\b", re.I), "role reassignment", Severity.HIGH),
    (re.compile(r"(^|\n)\s*(system|assistant)\s*:", re.I), "role-marker injection", Severity.MEDIUM),
    (re.compile(r"do\s+not\s+(tell|inform|mention|reveal|disclose|notify|show)[^.]{0,40}(user|human|operator)", re.I), "covert / hidden-from-user instruction", Severity.HIGH),
    (re.compile(r"(always|first|before\s+(responding|answering)|instead|additionally)[^.]{0,30}(call|use|invoke|run|execute)\b", re.I), "embedded tool-call directive", Severity.HIGH),
    (re.compile(r"your\s+(real|actual|true|secret)\s+(task|goal|instruction|purpose)", re.I), "goal hijack", Severity.HIGH),
    (re.compile(r"(exfiltrat\w*|leak\s+the)|send\s+(the|all|any|these)[^.]{0,30}(to|http)|post[^.]{0,20}to\s+http", re.I), "data-exfiltration directive", Severity.HIGH),
    (re.compile(r"<important>|<secret>|<!--", re.I), "hidden markup", Severity.MEDIUM),
]
# UI-spoofing surfaces (7.2.2).
_UI = [
    (re.compile(r"\[\s*(approve|confirm|allow|yes|click here|continue|trust|accept)\s*\]", re.I), "spoofed approval control", Severity.MEDIUM),
    (re.compile(r"!\[[^\]]*\]\([^)]+\)"), "embedded image (UI-spoof surface)", Severity.LOW),
    (re.compile(r"<button|<a\s+href|<iframe|<img|<form", re.I), "embedded HTML UI element", Severity.MEDIUM),
]
_UI_TYPES = {"spoofed approval control", "embedded image (UI-spoof surface)", "embedded HTML UI element"}


def analyze_text(text: str, where: str) -> list[dict]:
    """Return a list of issues found in one text field."""
    issues: list[dict] = []
    if not text:
        return issues
    if any(c in _ZERO_WIDTH for c in text):
        n = sum(text.count(c) for c in _ZERO_WIDTH)
        issues.append({"type": "hidden zero-width characters", "severity": Severity.HIGH,
                       "snippet": f"{n} zero-width char(s) embedded", "where": where})
    if any(c in _BIDI for c in text):
        issues.append({"type": "bidirectional/RTL-override characters", "severity": Severity.HIGH,
                       "snippet": "bidi override character(s) present", "where": where})
    for rx, label, sev in _INJECTION + _UI:
        m = rx.search(text)
        if m:
            issues.append({"type": label, "severity": sev, "snippet": m.group(0).strip()[:120], "where": where})
    return issues


class ToolPoisonScanner(BaseScanner):
    name = "POISON"

    async def scan(self, inventory: ServerInventory) -> list[Finding]:
        self._findings = []
        for tool in inventory.tools:
            name = tool.get("name", "")
            texts = [(tool.get("description", "") or "", f"tool '{name}' description")]
            schema = tool.get("inputSchema", {}) or {}
            for pname, pdef in (schema.get("properties", {}) or {}).items():
                texts.append(((pdef or {}).get("description", "") or "", f"tool '{name}' param '{pname}'"))
            self._emit(name, f"Tool: {name}", texts)
        for prompt in inventory.prompts:
            pname = prompt.get("name", "")
            self._emit(pname, f"Prompt: {pname}", [(prompt.get("description", "") or "", f"prompt '{pname}' description")])
        return self._findings

    def scan_contents(self, name: str, component: str, text: str) -> None:
        """Scan fetched resource / tool-output content for rendered instructions (7.2.2)."""
        self._emit(name, component, [(text or "", f"content of {name}")])

    def _emit(self, name: str, component: str, texts: list[tuple[str, str]]) -> None:
        issues: list[dict] = []
        for text, where in texts:
            issues.extend(analyze_text(text, where))
        if not issues:
            return
        sev = max((i["severity"] for i in issues), key=lambda s: s.numeric)
        all_ui = all(i["type"] in _UI_TYPES for i in issues)
        kind = "MCP Apps UI Poisoning/Spoofing" if all_ui else "Tool Description Poisoning"
        cats = [AbuseCategory.PROMPT_INJECTION]
        if any("exfiltrat" in i["type"] for i in issues):
            cats.append(AbuseCategory.DATA_EXFILTRATION)
        evidence = "Injected / obfuscated content in MCP metadata:\n" + "\n".join(
            f"- [{i['severity'].value}] {i['type']} in {i['where']}: {i['snippet']!r}" for i in issues
        )
        self._findings.append(Finding(
            id=self._next_id(),
            title=f"{kind}: '{name}'",
            severity=sev,
            affected_component=component,
            evidence=evidence,
            reproduction_steps=[
                "# A consuming AI client reads tool/prompt descriptions as trusted context",
                f"# Inspect the flagged metadata on '{name}'",
                "# The injected text can steer the client's tool calls or output",
            ],
            impact=("Injected instructions in server-supplied metadata can hijack a consuming LLM client — "
                    "triggering unauthorized tool calls or data exfiltration without the user's awareness."),
            remediation=("Treat all server-supplied descriptions as untrusted: strip control/zero-width characters, "
                         "never render HTML, and don't let descriptions influence tool-selection decisions."),
            abuse_categories=cats,
            risk_score=8.0 if sev == Severity.HIGH else 5.5,
            tags=["tool-poisoning", "mcp-7.2"],
        ))
