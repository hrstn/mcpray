"""Report-bundle test — ATLAS/OWASP tags + verbatim wire transcript."""
from mcpray.findings import (
    AbuseCategory,
    Finding,
    ScanResult,
    ServerInventory,
    Severity,
)
from mcpray.reporters import bundle_reporter


def _result():
    inv = ServerInventory(
        target="http://t/mcp", transport="HTTP", auth_required=False,
        tools=[{"name": "run_cmd"}], resources=[], resource_templates=[], prompts=[],
    )
    finding = Finding(
        id="ACT-001", title="Command Injection in run_cmd",
        severity=Severity.CRITICAL, affected_component="tool:run_cmd",
        evidence="MALICIOUS_EVIDENCE: whoami returned root",
        reproduction_steps=["Call run_cmd with cmd='; id'", "Observe uid=0"],
        impact="Full RCE", remediation="Sanitize input",
        abuse_categories=[AbuseCategory.REMOTE_EXECUTION],
        risk_score=9.5,
    )
    wire = [{
        "ts": "2026-07-17T00:00:00Z", "op": "call_tool", "target": "run_cmd",
        "params": {"tool": "run_cmd", "arguments": {"cmd": "id; cat /etc/passwd"}},
        "ok": True, "response": "uid=0(root) gid=0(root)\nroot:x:0:0:root:/root:/bin/bash",
        "error": None, "latency_ms": 12,
    }]
    return ScanResult(
        target="http://t/mcp", scan_timestamp="2026-07-17T00:00:00Z", scanner_version="1.0.0",
        findings=[finding], tool_abuse_factors=[], server_inventory=inv, attack_paths=[],
        overall_risk_score=9.5, risk_level=Severity.CRITICAL, active_testing_enabled=True,
        wire_log=wire,
    )


def test_bundle_tags_and_verbatim_wire_log():
    md = bundle_reporter.render(_result())
    # ATLAS + OWASP tags on the finding
    assert "AML.T0053" in md
    assert "LLM06" in md
    # finding evidence verbatim
    assert "MALICIOUS_EVIDENCE" in md
    # verbatim wire transcript: request payload AND response both present in full
    assert "id; cat /etc/passwd" in md
    assert "uid=0(root)" in md
    assert "root:x:0:0:" in md
    assert "Appendix — Wire Transcript" in md


def test_bundle_roundtrips_through_json():
    # to_dict includes wire_log so a saved scan can be re-bundled later.
    d = _result().to_dict()
    assert d["wire_log"][0]["params"]["arguments"]["cmd"] == "id; cat /etc/passwd"
