from datetime import UTC, datetime

from onyx.server.security.serializers import serialize_security_row


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
