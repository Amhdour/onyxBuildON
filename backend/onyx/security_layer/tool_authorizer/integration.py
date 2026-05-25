from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any

from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.findings.models import SecurityFinding
from onyx.security_layer.context import SecurityContext
from onyx.security_layer.tool_authorizer.authorizer import ToolAuthorizationResult
from onyx.security_layer.tool_authorizer.authorizer import ToolAuthorizer
from onyx.security_layer.mode import is_security_layer_enabled
from onyx.security_layer.mode import is_enforce_mode
from onyx.security_layer.mode import is_observe_mode
from onyx.security_layer.mode import should_fail_closed
from onyx.security_layer.mode import should_fail_open
from onyx.configs import app_configs
from onyx.security_layer.persistence_service import SecurityPersistenceService


def approve_tool_request_once(tool_name: str, tool_args: dict[str, Any], user_id: str, tenant_id: str, session_id: str) -> str:
    row = SecurityPersistenceService().create_approval_request(
        tenant_id=tenant_id,
        user_id=user_id,
        session_id=session_id,
        tool_name=tool_name,
        action="execute",
        resource=tool_name,
        tool_args=tool_args,
    )
    SecurityPersistenceService().set_approval_status(row.id, "approved")
    return row.id


@dataclass
class ToolAuthorizationGateResult:
    outcome: DecisionType
    audit_events: list[AuditEvent]
    finding: SecurityFinding | None


def run_tool_authorization_gate(
    tool_name: str,
    tool_args: dict[str, Any],
    user_id: str | None,
    session_id: str | None,
    tenant_id: str | None,
    merged_tool_call: dict[str, Any] | None,
    *,
    audit_service: AuditService | None = None,
) -> ToolAuthorizationGateResult:
    security_enabled = is_security_layer_enabled()

    audit = audit_service or AuditService()

    context = SecurityContext(
        actor_user_id=user_id,
        tenant_id=tenant_id,
        session_id=session_id,
        surface="tool_execution",
        action="execute",
        resource_type="tool",
        resource_id=tool_name,
        tool_name=tool_name,
        metadata={"merged": merged_tool_call is not None},
    )
    proposed_event = audit.record(
        AuditEvent(
            event_type="tool_call_proposed",
            tenant_id=context.tenant_id,
            user_id=context.actor_user_id,
            session_id=context.session_id,
            decision_id="pending",
            resource_type="tool",
            resource_id=tool_name,
            action="execute",
            risk_level="unknown",
            details=context.to_audit_metadata(),
        )
    )

    require_context = os.getenv(
        "SECURITY_LAYER_REQUIRE_CONTEXT",
        str(app_configs.SECURITY_LAYER_REQUIRE_CONTEXT),
    ).strip().lower() in {"1", "true", "yes", "on"}
    missing_hard = (user_id in {None, "missing:user"}) or (tenant_id in {None, "missing:tenant"})

    if missing_hard and require_context and is_enforce_mode():
        blocked_event = audit.record(
            AuditEvent(
                event_type="tool_call_denied_missing_context",
                tenant_id=context.tenant_id,
                user_id=context.actor_user_id,
                session_id=context.session_id,
                decision_id="default:missing_context:deny",
                resource_type="tool",
                resource_id=tool_name,
                action="execute",
                risk_level="high",
                details=context.to_audit_metadata(),
            )
        )
        return ToolAuthorizationGateResult(outcome=DecisionType.DENY, audit_events=[proposed_event, blocked_event], finding=None)

    if not security_enabled:
        return ToolAuthorizationGateResult(outcome=DecisionType.ALLOW, audit_events=[proposed_event], finding=None)

    authorizer = ToolAuthorizer(audit_service=audit)
    try:
        result: ToolAuthorizationResult = authorizer.authorize(
            tool_name=tool_name,
            tool_args=tool_args,
            user_id=user_id,
            session_id=session_id,
            tenant_id=tenant_id,
            merged_tool_call=merged_tool_call,
        )
    except Exception as e:
        error_event = audit.record(
            AuditEvent(
                event_type="security.evaluation.error",
                tenant_id=context.tenant_id,
                user_id=context.actor_user_id,
                session_id=context.session_id,
                decision_id="error:tool_authorization",
                resource_type="tool",
                resource_id=tool_name,
                action="execute",
                risk_level="high",
                details={**context.to_audit_metadata(), "error": str(e)},
            )
        )
        if should_fail_open():
            return ToolAuthorizationGateResult(outcome=DecisionType.ALLOW, audit_events=[proposed_event, error_event], finding=None)
        if should_fail_closed():
            return ToolAuthorizationGateResult(outcome=DecisionType.DENY, audit_events=[proposed_event, error_event], finding=None)
        return ToolAuthorizationGateResult(outcome=DecisionType.ALLOW, audit_events=[proposed_event, error_event], finding=None)

    should_block = (not is_observe_mode()) and result.decision.decision in {
        DecisionType.DENY,
        DecisionType.REQUIRE_APPROVAL,
    }

    if result.decision.decision == DecisionType.REQUIRE_APPROVAL:
        persistence = SecurityPersistenceService()
        approval_state, approval_row = persistence.consume_matching_approved_request(
            tenant_id=tenant_id,
            user_id=user_id,
            session_id=session_id,
            tool_name=tool_name,
            action="execute",
            resource=tool_name,
            tool_args=tool_args,
        )
        if approval_state == "approved_and_consumed" and approval_row is not None:
            audit.record(AuditEvent(event_type="approval_consumed", tenant_id=context.tenant_id, user_id=context.actor_user_id, session_id=context.session_id, decision_id=approval_row.id, resource_type="tool", resource_id=tool_name, action="execute", risk_level="medium", details=context.to_audit_metadata()))
            return ToolAuthorizationGateResult(outcome=DecisionType.ALLOW, audit_events=[proposed_event, result.audit_event], finding=result.finding)
        if is_enforce_mode():
            if approval_state == "missing":
                new_req = persistence.create_approval_request(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    session_id=session_id,
                    tool_name=tool_name,
                    action="execute",
                    resource=tool_name,
                    tool_args=tool_args,
                )
                audit.record(AuditEvent(event_type="approval_requested", tenant_id=context.tenant_id, user_id=context.actor_user_id, session_id=context.session_id, decision_id=new_req.id, resource_type="tool", resource_id=tool_name, action="execute", risk_level="high", details={**context.to_audit_metadata(), "approval_state": approval_state}))
            else:
                event_type = "approval_denied" if approval_state == "denied" else "approval_expired" if approval_state == "expired" else "approval_consumed"
                audit.record(AuditEvent(event_type=event_type, tenant_id=context.tenant_id, user_id=context.actor_user_id, session_id=context.session_id, decision_id=approval_row.id if approval_row else "missing", resource_type="tool", resource_id=tool_name, action="execute", risk_level="high", details={**context.to_audit_metadata(), "approval_state": approval_state}))
            return ToolAuthorizationGateResult(outcome=DecisionType.REQUIRE_APPROVAL, audit_events=[proposed_event, result.audit_event], finding=result.finding)

    if is_observe_mode():
        outcome = DecisionType.ALLOW
    elif should_block:
        outcome = result.decision.decision
    else:
        outcome = DecisionType.ALLOW

    return ToolAuthorizationGateResult(
        outcome=outcome,
        audit_events=[proposed_event, result.audit_event],
        finding=result.finding,
    )
