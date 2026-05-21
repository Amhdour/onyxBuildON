from __future__ import annotations

from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.audit.redaction import redact_details


class AuditService:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> AuditEvent:
        event.details = redact_details(event.details)
        self._events.append(event)
        return event

    def list_all(self) -> list[AuditEvent]:
        return list(self._events)
