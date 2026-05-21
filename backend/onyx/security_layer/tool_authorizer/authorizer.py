from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.decisions.models import RiskLevel
from onyx.security_layer.decisions.models import SecurityDecision
from onyx.security_layer.findings.models import SecurityFinding
from onyx.security_layer.findings.service import FindingService
from onyx.security_layer.tool_authorizer.argument_scanner import scan_tool_arguments
from onyx.security_layer.tool_authorizer.classifier import RISK_BY_CLASSIFICATION
from onyx.security_layer.tool_authorizer.classifier import classify_tool_risk


@dataclass
class ToolAuthorizationResult:
    decision: SecurityDecision
    audit_event: AuditEvent
    finding: SecurityFinding | None


class ToolAuthorizer:
    def __init__(self, audit_service: AuditService | None = None, finding_service: FindingService | None = None) -> None:
        self.audit_service = audit_service or AuditService()
        self.finding_service = finding_service or FindingService()

    def authorize(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        user_id: str | None = None,
        session_id: str | None = None,
        tenant_id: str | None = None,
        merged_tool_call: dict[str, Any] | None = None,
    ) -> ToolAuthorizationResult:
        classification = classify_tool_risk(tool_name)
        scan_findings = scan_tool_arguments(tool_args)
        risk_level = RISK_BY_CLASSIFICATION[classification]

        decision_type = DecisionType.ALLOW
        reason = f"Tool classified as {classification}"

        if scan_findings:
            decision_type = DecisionType.DENY
            risk_level = RiskLevel.CRITICAL
            reason = "Sensitive or suspicious arguments detected"
        elif classification in {"admin_action", "credential_access", "deployment", "critical"}:
            decision_type = DecisionType.DENY
            reason = f"{classification} tools are denied"
        elif classification in {"file_write", "code_execution", "external_write", "data_export"}:
            decision_type = DecisionType.REQUIRE_APPROVAL
            reason = f"{classification} tools require approval"

        decision = SecurityDecision(
            decision=decision_type,
            risk_level=risk_level,
            reason=reason,
            policy_id="tool_authorization_default",
            matched_rules=[classification],
            evidence={
                "classification": classification,
                "scan_findings": ",".join(scan_findings),
                "merged": merged_tool_call is not None,
            },
            subject_type="user",
            subject_id=user_id or "unknown",
            tenant_id=tenant_id or "default",
            session_id=session_id or "default",
            resource_type="tool",
            resource_id=tool_name,
            action="execute",
        )

        event_type = "tool_call_allowed"
        if decision.decision == DecisionType.DENY:
            event_type = "tool_call_denied"
        elif decision.decision == DecisionType.REQUIRE_APPROVAL:
            event_type = "tool_call_requires_approval"

        audit_event = self.audit_service.record(
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

        finding = None
        if decision.decision == DecisionType.DENY and decision.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            finding = self.finding_service.create_from_decision(decision)

        return ToolAuthorizationResult(decision=decision, audit_event=audit_event, finding=finding)
