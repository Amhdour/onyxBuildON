from __future__ import annotations

from dataclasses import dataclass

from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.decisions.models import SecurityDecision


@dataclass
class MCPAuditLogger:
    audit_service: AuditService

    def record_proposed(self, *, tenant_id: str, user_id: str, session_id: str, action: str) -> AuditEvent:
        return self.audit_service.record(
            AuditEvent(
                event_type="mcp_call_proposed",
                tenant_id=tenant_id,
                user_id=user_id,
                session_id=session_id,
                decision_id="pending",
                resource_type="mcp_action",
                resource_id=action,
                action="execute",
                risk_level="unknown",
                details={},
            )
        )

    def record_decision(self, decision: SecurityDecision) -> AuditEvent:
        event_type = "mcp_call_allowed" if decision.decision == DecisionType.ALLOW else "mcp_call_denied"
        return self.audit_service.record(
            AuditEvent(
                event_type=event_type,
                tenant_id=decision.tenant_id,
                user_id=decision.subject_id,
                session_id=decision.session_id,
                decision_id=decision.decision_id,
                resource_type=decision.resource_type,
                resource_id=decision.resource_id,
                action=decision.action,
                risk_level=decision.risk_level.value,
                details=decision.evidence,
            )
        )
