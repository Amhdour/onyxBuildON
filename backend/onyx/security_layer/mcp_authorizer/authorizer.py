from __future__ import annotations

import os
from dataclasses import dataclass

from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.decisions.models import RiskLevel
from onyx.security_layer.decisions.models import SecurityDecision
from onyx.security_layer.findings.models import SecurityFinding
from onyx.security_layer.findings.service import FindingService
from onyx.security_layer.mcp_authorizer.audit import MCPAuditLogger
from onyx.security_layer.mcp_authorizer.scopes import MCPScope
from onyx.security_layer.mcp_authorizer.scopes import required_scope_for_action
from onyx.security_layer.mcp_authorizer.session import MCPSession
from onyx.security_layer.policy.context import PolicyContext
from onyx.security_layer.policy.engine import PolicyEngine


@dataclass
class MCPAuthorizationResult:
    outcome: DecisionType
    proposed_event_type: str
    decision_event_type: str
    finding: SecurityFinding | None


class MCPAuthorizer:
    def __init__(self, policy_engine: PolicyEngine, audit_logger: MCPAuditLogger, finding_service: FindingService | None = None) -> None:
        self._policy_engine = policy_engine
        self._audit_logger = audit_logger
        self._finding_service = finding_service or FindingService()

    def authorize(self, session: MCPSession, action: str) -> MCPAuthorizationResult:
        proposed = self._audit_logger.record_proposed(
            tenant_id=session.tenant_id,
            user_id=session.user_id,
            session_id=session.session_id,
            action=action,
        )

        required_scope = required_scope_for_action(action)
        if required_scope == MCPScope.ADMIN:
            decision = self._build_decision(session, action, DecisionType.DENY, RiskLevel.CRITICAL, "mcp:admin denied by policy", required_scope.value)
        elif not session.has_scope(required_scope.value):
            decision = self._build_decision(session, action, DecisionType.DENY, RiskLevel.HIGH, "missing required scope", required_scope.value)
        elif required_scope in {MCPScope.FILE_WRITE, MCPScope.CODE_EXECUTE}:
            decision = self._build_decision(session, action, DecisionType.REQUIRE_APPROVAL, RiskLevel.HIGH, "high-risk action requires approval", required_scope.value)
        else:
            policy_context = PolicyContext(
                tenant_id=session.tenant_id,
                session_id=session.session_id,
                subject_type="mcp_client",
                subject_id=session.user_id,
                resource_type="mcp_action",
                resource_id=action,
                action="execute",
                metadata={"required_scope": required_scope.value, "client_id": session.client_id},
            )
            policy_decision = self._policy_engine.evaluate(policy_context)
            decision = self._build_decision(
                session,
                action,
                policy_decision.decision,
                policy_decision.risk_level,
                policy_decision.reason,
                required_scope.value,
            )

        event = self._audit_logger.record_decision(decision)
        finding = None
        if decision.decision == DecisionType.DENY and decision.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            finding = self._finding_service.create_from_decision(decision)

        return MCPAuthorizationResult(outcome=decision.decision, proposed_event_type=proposed.event_type, decision_event_type=event.event_type, finding=finding)

    def _build_decision(self, session: MCPSession, action: str, decision: DecisionType, risk_level: RiskLevel, reason: str, required_scope: str) -> SecurityDecision:
        return SecurityDecision(
            decision=decision,
            risk_level=risk_level,
            reason=reason,
            policy_id="mcp_authorization_default",
            matched_rules=[required_scope],
            evidence={"required_scope": required_scope},
            subject_type="mcp_client",
            subject_id=session.user_id,
            tenant_id=session.tenant_id,
            session_id=session.session_id,
            resource_type="mcp_action",
            resource_id=action,
            action="execute",
        )


def is_mcp_auth_enabled() -> bool:
    return os.getenv("SECURITY_MCP_AUTH_ENABLED", "true").lower() == "true"
