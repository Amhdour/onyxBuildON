from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.tool_authorizer.authorizer import ToolAuthorizer
from onyx.security_layer.tool_authorizer.integration import run_tool_authorization_gate


def test_read_only_tool_allowed() -> None:
    result = ToolAuthorizer().authorize("read_file", {"path": "/tmp/a"})
    assert result.decision.decision == DecisionType.ALLOW


def test_retrieval_tool_allowed() -> None:
    result = ToolAuthorizer().authorize("search_docs", {"queries": ["onyx"]})
    assert result.decision.decision == DecisionType.ALLOW


def test_file_write_requires_approval() -> None:
    result = ToolAuthorizer().authorize("write_file", {"path": "/tmp/a"})
    assert result.decision.decision == DecisionType.REQUIRE_APPROVAL


def test_code_execution_requires_approval() -> None:
    result = ToolAuthorizer().authorize("python_executor", {"code": "print('x')"})
    assert result.decision.decision == DecisionType.REQUIRE_APPROVAL


def test_admin_action_denied() -> None:
    result = ToolAuthorizer().authorize("admin_delete_user", {})
    assert result.decision.decision == DecisionType.DENY


def test_credential_access_denied() -> None:
    result = ToolAuthorizer().authorize("credential_lookup", {})
    assert result.decision.decision == DecisionType.DENY


def test_deployment_denied() -> None:
    result = ToolAuthorizer().authorize("deploy_release", {})
    assert result.decision.decision == DecisionType.DENY


def test_secret_in_tool_arguments_denied() -> None:
    result = ToolAuthorizer().authorize("read_file", {"authorization": "Bearer supersecrettokenvalue"})
    assert result.decision.decision == DecisionType.DENY


def test_merged_tool_call_is_authorized_after_merge(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_ENABLED", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "enforce")
    gate_result = run_tool_authorization_gate(
        tool_name="search_tool",
        tool_args={"queries": ["q1", "q2"]},
        user_id="u1",
        session_id="s1",
        tenant_id="t1",
        merged_tool_call={"tool_name": "search_tool", "tool_args": {"queries": ["q1", "q2"]}},
    )
    assert gate_result.outcome == DecisionType.ALLOW


def test_denied_tool_creates_audit_event() -> None:
    service = AuditService()
    run_tool_authorization_gate(
        tool_name="admin_tool",
        tool_args={},
        user_id="u1",
        session_id="s1",
        tenant_id="t1",
        merged_tool_call={"x": 1},
        audit_service=service,
    )
    assert any(event.event_type == "tool_call_denied" for event in service.list_all())


def test_denied_high_risk_tool_creates_finding() -> None:
    result = ToolAuthorizer().authorize("deployment_tool", {})
    assert result.finding is not None


def test_security_layer_disabled_preserves_existing_behavior(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_ENABLED", "false")
    gate_result = run_tool_authorization_gate(
        tool_name="admin_tool",
        tool_args={},
        user_id="u1",
        session_id="s1",
        tenant_id="t1",
        merged_tool_call={"x": 1},
    )
    assert gate_result.outcome == DecisionType.ALLOW
