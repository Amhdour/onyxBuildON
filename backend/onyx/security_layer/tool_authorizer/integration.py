from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.findings.models import SecurityFinding
from onyx.security_layer.tool_authorizer.authorizer import ToolAuthorizationResult
from onyx.security_layer.tool_authorizer.authorizer import ToolAuthorizer


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
    security_enabled = os.getenv("SECURITY_LAYER_ENABLED", "true").lower() == "true"
    mode = os.getenv("SECURITY_LAYER_MODE", "enforce").lower()

    audit = audit_service or AuditService()

    proposed_event = audit.record(
        AuditEvent(
            event_type="tool_call_proposed",
            tenant_id=tenant_id or "default",
            user_id=user_id or "unknown",
            session_id=session_id or "default",
            decision_id="pending",
            resource_type="tool",
            resource_id=tool_name,
            action="execute",
            risk_level="unknown",
            details={"merged": merged_tool_call is not None},
        )
    )

    if not security_enabled:
        return ToolAuthorizationGateResult(outcome=DecisionType.ALLOW, audit_events=[proposed_event], finding=None)

    authorizer = ToolAuthorizer(audit_service=audit)
    result: ToolAuthorizationResult = authorizer.authorize(
        tool_name=tool_name,
        tool_args=tool_args,
        user_id=user_id,
        session_id=session_id,
        tenant_id=tenant_id,
        merged_tool_call=merged_tool_call,
    )

    should_block = mode in {"enforce", "block"} and result.decision.decision in {
        DecisionType.DENY,
        DecisionType.REQUIRE_APPROVAL,
    }

    if mode in {"observe", "warn"}:
        outcome = DecisionType.ALLOW
    elif should_block:
        outcome = result.decision.decision
    else:
        outcome = DecisionType.ALLOW

    return ToolAuthorizationGateResult(
        outcome=outcome,
        audit_events=[proposed_event, result.audit_event],
        finding=result.finding if mode in {"warn", "enforce", "block"} else None,
    )
