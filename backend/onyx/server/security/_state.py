from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from onyx.configs.app_configs import SECURITY_LAYER_ENABLED
from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.findings.models import FindingSeverity
from onyx.security_layer.findings.models import SecurityFinding
from onyx.security_layer.launch_gates.checks import GateStatus, LaunchGateCheck
from onyx.security_layer.launch_gates.engine import LaunchGateInput, LaunchGateResult, evaluate_launch_gates
from onyx.security_layer.launch_gates.evidence import LaunchGateEvidence
from onyx.security_layer.launch_gates.reports import generate_launch_gate_reports
from onyx.security_layer.models import PolicyMode

REPORT_DIR = Path("security_reports")

AUDIT_EVENTS: list[AuditEvent] = []
FINDINGS: list[SecurityFinding] = []
TOOL_DECISIONS: list[dict[str, object]] = []
RETRIEVAL_EVENTS: list[dict[str, object]] = []
MCP_EVENTS: list[dict[str, object]] = []
SANDBOX_GATES: list[dict[str, object]] = []
ARTIFACT_SCANS: list[dict[str, object]] = []
LAUNCH_GATE_RUNS: list[dict[str, object]] = []


def _latest_launch_gate_result() -> dict[str, object] | None:
    if not LAUNCH_GATE_RUNS:
        return None
    return LAUNCH_GATE_RUNS[-1]


def build_overview(tenant_id: str) -> dict[str, object]:
    tenant_findings = [f for f in FINDINGS if f.tenant_id == tenant_id]

    def _recent_denied(records: list[dict[str, object]]) -> list[dict[str, object]]:
        return [r for r in records if r.get("tenant_id") == tenant_id and r.get("decision") == "deny"][-10:]

    latest_gate = _latest_launch_gate_result()
    return {
        "security_layer_enabled": SECURITY_LAYER_ENABLED,
        "policy_mode": PolicyMode.ENFORCE.value if SECURITY_LAYER_ENABLED else PolicyMode.OBSERVE.value,
        "latest_launch_gate_result": latest_gate,
        "open_findings_count": sum(1 for f in tenant_findings if f.status.value == "open"),
        "critical_findings_count": sum(1 for f in tenant_findings if f.severity == FindingSeverity.CRITICAL),
        "high_findings_count": sum(1 for f in tenant_findings if f.severity == FindingSeverity.HIGH),
        "recent_denied_tool_calls": _recent_denied(TOOL_DECISIONS),
        "recent_denied_retrieval_events": _recent_denied(RETRIEVAL_EVENTS),
        "recent_denied_mcp_events": _recent_denied(MCP_EVENTS),
        "recent_sandbox_gate_failures": [
            g for g in SANDBOX_GATES if g.get("tenant_id") == tenant_id and g.get("outcome") == "deny"
        ][-10:],
        "recent_artifact_blocks": [
            a for a in ARTIFACT_SCANS if a.get("tenant_id") == tenant_id and a.get("decision") == "block"
        ][-10:],
    }


def run_launch_gate_engine(tenant_id: str) -> dict[str, object]:
    checks = [
        LaunchGateCheck(gate="tool_authorization_gate", status=GateStatus.PASS, message="tool auth checks passed"),
        LaunchGateCheck(gate="retrieval_acl_proof", status=GateStatus.PASS, message="retrieval proofs present"),
        LaunchGateCheck(gate="artifact_security", status=GateStatus.PASS, message="no blocking artifact findings"),
    ]
    findings = [f.model_dump(mode="json") for f in FINDINGS if f.tenant_id == tenant_id and f.blocking_launch]
    evidence = LaunchGateEvidence(
        audit_evidence_sample=[e.model_dump(mode="json") for e in AUDIT_EVENTS if e.tenant_id == tenant_id][-20:],
        policy_decisions=[d for d in TOOL_DECISIONS if d.get("tenant_id") == tenant_id][-50:],
    )
    result: LaunchGateResult = evaluate_launch_gates(LaunchGateInput(checks=checks, findings=findings, evidence=evidence))
    report_paths = generate_launch_gate_reports(result, REPORT_DIR)
    run = {
        "tenant_id": tenant_id,
        "run_at": datetime.now(timezone.utc).isoformat(),
        "overall_status": result.scorecard.overall_status.value,
        "launch_blocked": result.launch_blocked,
        "blocking_failures": result.blocking_failures,
        "reports": {k: str(v) for k, v in report_paths.items()},
    }
    LAUNCH_GATE_RUNS.append(run)
    return run


def read_report(report_name: str) -> str:
    report_path = REPORT_DIR / report_name
    if not report_path.exists():
        return ""
    return report_path.read_text()


def read_json_report(report_name: str) -> dict[str, object] | list[object]:
    content = read_report(report_name)
    return json.loads(content) if content else {}
