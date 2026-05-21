from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.tool_authorizer.authorizer import ToolAuthorizer
from onyx.security_layer.tool_authorizer.integration import ToolAuthorizer as IntegrationToolAuthorizer
from onyx.security_layer.persistence_service import SecurityPersistenceService
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


def test_observe_mode_allows_denied_decision(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_ENABLED", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "observe")
    result = run_tool_authorization_gate(
        tool_name="admin_tool",
        tool_args={},
        user_id="u1",
        session_id="s1",
        tenant_id="t1",
        merged_tool_call=None,
    )
    assert result.outcome == DecisionType.ALLOW


def test_enforce_mode_denies_high_risk_tool(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_ENABLED", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "enforce")
    result = run_tool_authorization_gate(
        tool_name="admin_tool",
        tool_args={},
        user_id="u1",
        session_id="s1",
        tenant_id="t1",
        merged_tool_call=None,
    )
    assert result.outcome == DecisionType.DENY


def test_exception_in_observe_mode_allows(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_ENABLED", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "observe")
    def _raise(*args: object, **kwargs: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(IntegrationToolAuthorizer, "authorize", _raise)
    result = run_tool_authorization_gate(
        tool_name="read_file",
        tool_args={},
        user_id="u1",
        session_id="s1",
        tenant_id="t1",
        merged_tool_call=None,
    )
    assert result.outcome == DecisionType.ALLOW
    assert any(event.event_type == "security.evaluation.error" for event in result.audit_events)


def test_exception_in_enforce_mode_denies_when_fail_closed(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_ENABLED", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "enforce")
    monkeypatch.setenv("SECURITY_LAYER_FAIL_CLOSED_IN_ENFORCE", "true")
    def _raise(*args: object, **kwargs: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(IntegrationToolAuthorizer, "authorize", _raise)
    result = run_tool_authorization_gate(
        tool_name="read_file",
        tool_args={},
        user_id="u1",
        session_id="s1",
        tenant_id="t1",
        merged_tool_call=None,
    )
    assert result.outcome == DecisionType.DENY


def test_enforce_mode_blocks_missing_required_context(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_ENABLED", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "enforce")
    monkeypatch.setenv("SECURITY_LAYER_REQUIRE_CONTEXT", "true")
    result = run_tool_authorization_gate(
        tool_name="read_file",
        tool_args={},
        user_id="missing:user",
        session_id="s1",
        tenant_id="missing:tenant",
        merged_tool_call=None,
    )
    assert result.outcome == DecisionType.DENY


def test_approval_lifecycle_allows_once(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_ENABLED", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "enforce")

    first = run_tool_authorization_gate(
        tool_name="write_file",
        tool_args={"path": "/tmp/a"},
        user_id="u1",
        session_id="s1",
        tenant_id="t1",
        merged_tool_call=None,
    )
    assert first.outcome == DecisionType.REQUIRE_APPROVAL

    from onyx.security_layer.tool_authorizer.integration import approve_tool_request_once

    approve_tool_request_once("write_file", {"path": "/tmp/a"}, "u1", "t1", "s1")
    second = run_tool_authorization_gate(
        tool_name="write_file",
        tool_args={"path": "/tmp/a"},
        user_id="u1",
        session_id="s1",
        tenant_id="t1",
        merged_tool_call=None,
    )
    assert second.outcome == DecisionType.ALLOW

    third = run_tool_authorization_gate(
        tool_name="write_file",
        tool_args={"path": "/tmp/a"},
        user_id="u1",
        session_id="s1",
        tenant_id="t1",
        merged_tool_call=None,
    )
    assert third.outcome == DecisionType.REQUIRE_APPROVAL


def test_persistent_approval_request_created(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_ENABLED", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "enforce")
    calls = {}
    def _create(self, **kwargs):
        calls.update(kwargs)
        class _R: id = "a1"
        return _R()
    monkeypatch.setattr(SecurityPersistenceService, "create_approval_request", _create)
    monkeypatch.setattr(SecurityPersistenceService, "consume_matching_approved_request", lambda self, **kwargs: ("missing", None))
    run_tool_authorization_gate("write_file", {"path": "/tmp/a"}, "u1", "s1", "t1", None)
    assert calls["tool_name"] == "write_file"
    assert calls["tenant_id"] == "t1"


def test_approval_replay_hash_expired_denied(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_ENABLED", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "enforce")
    monkeypatch.setattr(SecurityPersistenceService, "consume_matching_approved_request", lambda self, **kwargs: ("approved_and_consumed", type("R", (), {"id": "a1"})()))
    assert run_tool_authorization_gate("write_file", {"path": "/tmp/a"}, "u1", "s1", "t1", None).outcome == DecisionType.ALLOW
    monkeypatch.setattr(SecurityPersistenceService, "consume_matching_approved_request", lambda self, **kwargs: ("consumed", type("R", (), {"id": "a1"})()))
    assert run_tool_authorization_gate("write_file", {"path": "/tmp/a"}, "u1", "s1", "t1", None).outcome == DecisionType.REQUIRE_APPROVAL
    monkeypatch.setattr(SecurityPersistenceService, "consume_matching_approved_request", lambda self, **kwargs: ("hash_mismatch", type("R", (), {"id": "a2"})()))
    assert run_tool_authorization_gate("write_file", {"path": "/tmp/b"}, "u1", "s1", "t1", None).outcome == DecisionType.REQUIRE_APPROVAL
    monkeypatch.setattr(SecurityPersistenceService, "consume_matching_approved_request", lambda self, **kwargs: ("expired", type("R", (), {"id": "a3"})()))
    assert run_tool_authorization_gate("write_file", {"path": "/tmp/c"}, "u1", "s1", "t1", None).outcome == DecisionType.REQUIRE_APPROVAL
    monkeypatch.setattr(SecurityPersistenceService, "consume_matching_approved_request", lambda self, **kwargs: ("denied", type("R", (), {"id": "a4"})()))
    assert run_tool_authorization_gate("write_file", {"path": "/tmp/d"}, "u1", "s1", "t1", None).outcome == DecisionType.REQUIRE_APPROVAL


def test_wrong_session_id_blocked(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_ENABLED", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "enforce")
    run_tool_authorization_gate("write_file", {"path": "/tmp/a"}, "u1", "s1", "t1", None)
    from onyx.security_layer.tool_authorizer.integration import approve_tool_request_once
    approve_tool_request_once("write_file", {"path": "/tmp/a"}, "u1", "t1", "s2")
    result = run_tool_authorization_gate("write_file", {"path": "/tmp/a"}, "u1", "s1", "t1", None)
    assert result.outcome == DecisionType.REQUIRE_APPROVAL
