from __future__ import annotations

from pathlib import Path

from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.decisions.models import RiskLevel
from onyx.security_layer.decisions.models import SecurityDecision
from onyx.security_layer.policy.context import PolicyContext
from onyx.security_layer.policy.loader import load_policy_directory
from onyx.security_layer.policy.models import PolicyDefinition
from onyx.security_layer.policy.models import PolicyMode
from onyx.security_layer.policy.rules import rule_matches


class PolicyEngine:
    def __init__(self, policies: list[PolicyDefinition]) -> None:
        self._policies = policies

    @classmethod
    def from_directory(cls, path: Path) -> "PolicyEngine":
        return cls(load_policy_directory(path))

    def evaluate(self, context: PolicyContext) -> SecurityDecision:
        for policy in self._policies:
            for rule in policy.rules:
                if not rule_matches(rule, context):
                    continue

                decision_type = DecisionType.ALLOW
                if policy.mode in {PolicyMode.ENFORCE, PolicyMode.BLOCK}:
                    decision_type = DecisionType(rule.decision.value)

                return SecurityDecision(
                    decision=decision_type,
                    risk_level=RiskLevel(rule.risk_level),
                    reason=rule.reason or f"Matched rule {rule.id}",
                    policy_id=policy.policy_id,
                    matched_rules=[rule.id],
                    evidence={"mode": policy.mode.value},
                    subject_type=context.subject_type,
                    subject_id=context.subject_id,
                    tenant_id=context.tenant_id,
                    session_id=context.session_id,
                    resource_type=context.resource_type,
                    resource_id=context.resource_id,
                    action=context.action,
                )

        return SecurityDecision(
            decision=DecisionType.ALLOW,
            risk_level=RiskLevel.LOW,
            reason="No rules matched",
            policy_id="default",
            matched_rules=[],
            evidence={},
            subject_type=context.subject_type,
            subject_id=context.subject_id,
            tenant_id=context.tenant_id,
            session_id=context.session_id,
            resource_type=context.resource_type,
            resource_id=context.resource_id,
            action=context.action,
        )
