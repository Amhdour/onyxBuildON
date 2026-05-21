import json

from onyx.security_layer.launch_gates import GateStatus
from onyx.security_layer.launch_gates import LaunchGateCheck
from onyx.security_layer.launch_gates import LaunchGateEvidence
from onyx.security_layer.launch_gates import LaunchGateInput
from onyx.security_layer.launch_gates import evaluate_launch_gates
from onyx.security_layer.launch_gates import generate_launch_gate_reports


def _sample_input(*, failing: bool) -> LaunchGateInput:
    checks = [
        LaunchGateCheck(gate="tool_authorization", status=GateStatus.PASS, message="ok"),
        LaunchGateCheck(
            gate="sandbox_security",
            status=GateStatus.FAIL if failing else GateStatus.PASS,
            message="Docker socket exposed" if failing else "sandbox secure",
            is_blocking=failing,
        ),
        LaunchGateCheck(
            gate="findings",
            status=GateStatus.WARNING,
            message="non-blocking findings",
        ),
    ]
    findings = [
        {
            "policy_id": "docker_socket_exposure",
            "severity": "critical",
            "title": "Docker socket exposed",
            "recommended_fix": "Disable docker socket mount",
        }
    ]
    evidence = LaunchGateEvidence(
        audit_evidence_sample=[{"event_type": "sandbox_gate_failed", "risk_level": "critical"}],
        policy_decisions=[{"decision": "deny", "policy_id": "sandbox", "reason": "socket"}],
    )
    return LaunchGateInput(checks=checks, findings=findings, evidence=evidence)


def test_launch_gate_pass_result() -> None:
    result = evaluate_launch_gates(_sample_input(failing=False))
    assert result.scorecard.overall_status == GateStatus.WARNING
    assert not result.launch_blocked


def test_launch_gate_fail_result() -> None:
    result = evaluate_launch_gates(_sample_input(failing=True))
    assert result.scorecard.overall_status == GateStatus.FAIL


def test_blocking_failure_blocks_launch() -> None:
    result = evaluate_launch_gates(_sample_input(failing=True))
    assert result.launch_blocked
    assert "Docker socket exposed" in result.blocking_failures


def test_reports_generated(tmp_path) -> None:
    result = evaluate_launch_gates(_sample_input(failing=True))
    outputs = generate_launch_gate_reports(result, tmp_path / "security_reports")

    assert outputs["launch_gate_report.json"].exists()
    assert outputs["launch_gate_report.md"].exists()
    assert outputs["security_findings.sarif"].exists()
    assert outputs["audit_sample.ndjson"].exists()
    assert outputs["policy_decisions.csv"].exists()


def test_json_report_generated(tmp_path) -> None:
    result = evaluate_launch_gates(_sample_input(failing=True))
    outputs = generate_launch_gate_reports(result, tmp_path / "security_reports")
    payload = json.loads(outputs["launch_gate_report.json"].read_text())
    assert payload["summary"]["fail_count"] == 1


def test_markdown_report_generated(tmp_path) -> None:
    result = evaluate_launch_gates(_sample_input(failing=True))
    outputs = generate_launch_gate_reports(result, tmp_path / "security_reports")
    assert "# Launch Gate Report" in outputs["launch_gate_report.md"].read_text()


def test_sarif_report_generated(tmp_path) -> None:
    result = evaluate_launch_gates(_sample_input(failing=True))
    outputs = generate_launch_gate_reports(result, tmp_path / "security_reports")
    payload = json.loads(outputs["security_findings.sarif"].read_text())
    assert payload["runs"][0]["results"][0]["ruleId"] == "docker_socket_exposure"


def test_ndjson_audit_sample_generated(tmp_path) -> None:
    result = evaluate_launch_gates(_sample_input(failing=True))
    outputs = generate_launch_gate_reports(result, tmp_path / "security_reports")
    assert "sandbox_gate_failed" in outputs["audit_sample.ndjson"].read_text()


def test_csv_policy_decisions_generated(tmp_path) -> None:
    result = evaluate_launch_gates(_sample_input(failing=True))
    outputs = generate_launch_gate_reports(result, tmp_path / "security_reports")
    assert "policy_id" in outputs["policy_decisions.csv"].read_text()


def test_sandbox_failures_appear_in_report(tmp_path) -> None:
    result = evaluate_launch_gates(_sample_input(failing=True))
    outputs = generate_launch_gate_reports(result, tmp_path / "security_reports")
    payload = json.loads(outputs["launch_gate_report.json"].read_text())
    assert "sandbox_security" in payload["failed_gates"]
    assert "Docker socket exposed" in payload["blocking_failures"]


def test_findings_appear_in_report(tmp_path) -> None:
    result = evaluate_launch_gates(_sample_input(failing=True))
    outputs = generate_launch_gate_reports(result, tmp_path / "security_reports")
    payload = json.loads(outputs["launch_gate_report.json"].read_text())
    assert payload["findings"][0]["title"] == "Docker socket exposed"
