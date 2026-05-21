from datetime import UTC, datetime

from onyx.server.security.serializers import serialize_security_row
from onyx.server.security.approvals import approve_request
from onyx.server.security.approvals import deny_request
from onyx.security_layer.persistence_service import SecurityPersistenceService


class _Row:
    def __init__(self) -> None:
        self._sa_instance_state = object()
        self.id = "1"
        self.created_at = datetime(2026, 1, 1, tzinfo=UTC)
        self.metadata_json = {"authorization": "Bearer token"}


def test_serializer_drops_sqlalchemy_state_and_redacts() -> None:
    out = serialize_security_row(_Row())
    assert "_sa_instance_state" not in out
    assert out["metadata_json"]["authorization"] == "[REDACTED]"


def test_approval_action_serialization(monkeypatch) -> None:
    class _User:
        id = "admin-1"

    class _Row:
        pass

    monkeypatch.setattr(SecurityPersistenceService, "set_approval_status", lambda self, approval_id, status, approved_by_user_id=None: _Row())
    approve_out = approve_request("a1", user=_User())
    deny_out = deny_request("a1", _=_User())
    assert approve_out == {"ok": True, "approval_id": "a1", "status": "approved"}
    assert deny_out == {"ok": True, "approval_id": "a1", "status": "denied"}
