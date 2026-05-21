from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.findings.service import FindingService
from onyx.security_layer.mcp_authorizer.audit import MCPAuditLogger
from onyx.security_layer.mcp_authorizer.authorizer import MCPAuthorizer
from onyx.security_layer.mcp_authorizer.authorizer import is_mcp_auth_enabled
from onyx.security_layer.mcp_authorizer.session import MCPSession
from onyx.security_layer.policy.engine import PolicyEngine


def _session(scopes: set[str]) -> MCPSession:
    return MCPSession(
        client_id="mcp-client",
        session_id="session-1",
        user_id="user-1",
        tenant_id="tenant-1",
        scopes=scopes,
    )


def _authorizer(audit_service: AuditService | None = None, finding_service: FindingService | None = None) -> MCPAuthorizer:
    return MCPAuthorizer(
        policy_engine=PolicyEngine(policies=[]),
        audit_logger=MCPAuditLogger(audit_service=audit_service or AuditService()),
        finding_service=finding_service,
    )


def test_mcp_search_allows_search() -> None:
    result = _authorizer().authorize(_session({"mcp:use", "mcp:search"}), "search_indexed_documents")
    assert result.outcome == DecisionType.ALLOW


def test_missing_scope_denies_action() -> None:
    result = _authorizer().authorize(_session({"mcp:use"}), "search_web")
    assert result.outcome == DecisionType.DENY


def test_file_write_requires_approval() -> None:
    result = _authorizer().authorize(_session({"mcp:use", "mcp:file_write"}), "file_write")
    assert result.outcome == DecisionType.REQUIRE_APPROVAL


def test_code_execute_requires_approval() -> None:
    result = _authorizer().authorize(_session({"mcp:use", "mcp:code_execute"}), "code_execute")
    assert result.outcome == DecisionType.REQUIRE_APPROVAL


def test_admin_denied() -> None:
    result = _authorizer().authorize(_session({"mcp:use", "mcp:admin"}), "admin")
    assert result.outcome == DecisionType.DENY


def test_audit_event_created() -> None:
    audit_service = AuditService()
    _authorizer(audit_service=audit_service).authorize(_session({"mcp:use", "mcp:search"}), "search_indexed_documents")
    events = audit_service.list_all()
    assert any(event.event_type == "mcp_call_proposed" for event in events)
    assert any(event.event_type == "mcp_call_allowed" for event in events)


def test_finding_created_for_denied_high_risk_mcp_call() -> None:
    finding_service = FindingService()
    result = _authorizer(finding_service=finding_service).authorize(_session({"mcp:use"}), "search_web")
    assert result.finding is not None


def test_security_mcp_auth_disabled_preserves_existing_behavior(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_MCP_AUTH_ENABLED", "false")
    assert is_mcp_auth_enabled() is False


def test_mcp_missing_context_denied_in_enforce_mode(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_REQUIRE_CONTEXT", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "enforce")
    sess = MCPSession(client_id="c", session_id="s", user_id="missing:user", tenant_id="missing:tenant", scopes={"mcp:use", "mcp:search"})
    result = _authorizer().authorize(sess, "search_indexed_documents")
    assert result.outcome == DecisionType.DENY


def test_mcp_missing_context_allowed_audited_in_observe_mode(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_LAYER_REQUIRE_CONTEXT", "true")
    monkeypatch.setenv("SECURITY_LAYER_MODE", "observe")
    audit = AuditService()
    sess = MCPSession(client_id="c", session_id="s", user_id="missing:user", tenant_id="missing:tenant", scopes={"mcp:use", "mcp:search"})
    result = _authorizer(audit_service=audit).authorize(sess, "search_indexed_documents")
    assert result.outcome == DecisionType.ALLOW
    assert len(audit.list_all()) >= 2
