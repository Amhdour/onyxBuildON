from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from onyx.db.engine.sql_engine import get_session_with_current_tenant
from onyx.db.security_layer import SecurityAuditEvent
from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.audit.redaction import redact_details
from onyx.security_layer.redaction import redact_security_payload


class AuditService:
    def create_audit_event(self, event: AuditEvent) -> AuditEvent:
        event.details = redact_security_payload(redact_details(event.details))
        with get_session_with_current_tenant() as db_session:
            db_session.add(
                SecurityAuditEvent(
                    id=event.event_id,
                    event_type=event.event_type,
                    severity=event.risk_level,
                    action=event.action,
                    decision=None,
                    reason=None,
                    actor_user_id=event.user_id,
                    tenant_id=event.tenant_id,
                    session_id=event.session_id,
                    correlation_id=event.details.get("correlation_id") if isinstance(event.details, dict) else None,
                    resource_type=event.resource_type,
                    resource_id=event.resource_id,
                    metadata_json=event.details,
                    created_at=event.created_at,
                )
            )
            db_session.commit()
        return event

    def record(self, event: AuditEvent) -> AuditEvent:
        return self.create_audit_event(event)

    def list_audit_events(self, filters: dict[str, Any] | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        filters = filters or {}
        with get_session_with_current_tenant() as db_session:
            stmt = select(SecurityAuditEvent).order_by(SecurityAuditEvent.created_at.desc()).limit(limit).offset(offset)
            if tenant_id := filters.get("tenant_id"):
                stmt = stmt.where(SecurityAuditEvent.tenant_id == str(tenant_id))
            if correlation_id := filters.get("correlation_id"):
                stmt = stmt.where(SecurityAuditEvent.correlation_id == str(correlation_id))
            if surface := filters.get("surface"):
                stmt = stmt.where(SecurityAuditEvent.resource_type == str(surface))
            rows = db_session.execute(stmt).scalars().all()
        return [{"id": r.id, "event_type": r.event_type, "severity": r.severity, "tenant_id": r.tenant_id, "actor_user_id": r.actor_user_id, "created_at": r.created_at.isoformat()} for r in rows]

    def list_all(self) -> list[AuditEvent]:
        rows = self.list_audit_events()
        return [AuditEvent(event_id=r["id"], event_type=r["event_type"], tenant_id=r.get("tenant_id") or "", user_id=r.get("actor_user_id") or "", session_id="", decision_id="", resource_type="", resource_id="", action="", risk_level=r["severity"], details={}, created_at=datetime.fromisoformat(r["created_at"])) for r in rows]
