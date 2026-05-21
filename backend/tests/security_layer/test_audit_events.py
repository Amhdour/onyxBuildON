from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.audit.service import AuditService


def test_audit_redaction() -> None:
    service = AuditService()
    event = AuditEvent(
        event_type="decision_made",
        tenant_id="t1",
        user_id="u1",
        session_id="s1",
        decision_id="d1",
        resource_type="tool",
        resource_id="r1",
        action="execute",
        risk_level="high",
        details={"token": "Bearer abc123", "password": "password=supersecret"},
    )
    stored = service.record(event)
    assert "abc123" not in str(stored.details)
    assert "supersecret" not in str(stored.details)
