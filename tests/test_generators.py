"""Nuclei/PoC generators emit templates for the new Phase-1/2 findings."""
from mcpray.findings import AbuseCategory, Finding, ScanResult, ServerInventory, Severity
from mcpray.reporters.nuclei_reporter import generate_nuclei_templates
from mcpray.reporters.poc_generator import generate_all_pocs


def _result(finding):
    inv = ServerInventory(target="http://t/mcp", transport="HTTP", auth_required=False,
                          tools=[{"name": "run_cmd"}], resources=[], resource_templates=[], prompts=[])
    return ScanResult(
        target="http://t/mcp", scan_timestamp="2026-07-17T00:00:00Z", scanner_version="1.0.0",
        findings=[finding], tool_abuse_factors=[], server_inventory=inv, attack_paths=[],
        overall_risk_score=finding.risk_score, risk_level=finding.severity,
    )


def _poison_finding():
    return Finding(
        id="POISON-001", title="Tool Description Poisoning: 'run_cmd'", severity=Severity.HIGH,
        affected_component="Tool: run_cmd", evidence="injected instruction override in description",
        reproduction_steps=["inspect tool metadata"], impact="hijack", remediation="sanitize",
        abuse_categories=[AbuseCategory.PROMPT_INJECTION], risk_score=8.0, tags=["tool-poisoning", "mcp-7.2"],
    )


def test_nuclei_generates_for_tool_poisoning(tmp_path):
    paths = generate_nuclei_templates(_result(_poison_finding()), str(tmp_path), min_severity=Severity.MEDIUM)
    assert len(paths) >= 1


def test_poc_generates_for_tool_poisoning(tmp_path):
    paths = generate_all_pocs(_result(_poison_finding()), str(tmp_path), min_severity=Severity.HIGH)
    assert len(paths) >= 1
