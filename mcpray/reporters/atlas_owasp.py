"""Best-effort MITRE ATLAS + OWASP-LLM-Top-10 (2025) tags for mcpray abuse
categories. Confirm ATLAS IDs against the current matrix before citing in a
report."""
from __future__ import annotations

_MAP: dict[str, dict[str, str]] = {
    "prompt_injection":       {"atlas": "AML.T0051", "atlas_name": "LLM Prompt Injection", "owasp": "LLM01", "owasp_name": "Prompt Injection"},
    "social_engineering":     {"atlas": "AML.T0054", "atlas_name": "LLM Jailbreak", "owasp": "LLM01", "owasp_name": "Prompt Injection"},
    "injection":              {"atlas": "AML.T0053", "atlas_name": "LLM Plugin Compromise", "owasp": "LLM06", "owasp_name": "Excessive Agency"},
    "remote_execution":       {"atlas": "AML.T0053", "atlas_name": "LLM Plugin Compromise", "owasp": "LLM06", "owasp_name": "Excessive Agency"},
    "privilege_escalation":   {"atlas": "AML.T0053", "atlas_name": "LLM Plugin Compromise", "owasp": "LLM06", "owasp_name": "Excessive Agency"},
    "lateral_movement":       {"atlas": "AML.T0053", "atlas_name": "LLM Plugin Compromise", "owasp": "LLM06", "owasp_name": "Excessive Agency"},
    "ssrf":                   {"atlas": "AML.T0053", "atlas_name": "LLM Plugin Compromise", "owasp": "LLM06", "owasp_name": "Excessive Agency"},
    "auth_bypass":            {"atlas": "AML.T0053", "atlas_name": "LLM Plugin Compromise", "owasp": "LLM06", "owasp_name": "Excessive Agency"},
    "credential_access":      {"atlas": "AML.T0057", "atlas_name": "LLM Data Leakage", "owasp": "LLM02", "owasp_name": "Sensitive Information Disclosure"},
    "data_exfiltration":      {"atlas": "AML.T0057", "atlas_name": "LLM Data Leakage", "owasp": "LLM02", "owasp_name": "Sensitive Information Disclosure"},
    "information_disclosure": {"atlas": "AML.T0057", "atlas_name": "LLM Data Leakage", "owasp": "LLM02", "owasp_name": "Sensitive Information Disclosure"},
    "dos":                    {"atlas": "AML.T0029", "atlas_name": "Denial of ML Service", "owasp": "LLM10", "owasp_name": "Unbounded Consumption"},
}


def tags_for(category: str) -> dict[str, str] | None:
    return _MAP.get(category)


def tag_line(categories: list[str]) -> str:
    """One-line ATLAS/OWASP tag string for a finding's abuse categories."""
    seen: list[str] = []
    for c in categories:
        t = _MAP.get(c)
        if not t:
            continue
        piece = f"**MITRE ATLAS** `{t['atlas']}` ({t['atlas_name']}) · **OWASP LLM** `{t['owasp']}` ({t['owasp_name']})"
        if piece not in seen:
            seen.append(piece)
    return "  \n".join(seen)
