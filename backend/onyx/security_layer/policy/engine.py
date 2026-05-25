from __future__ import annotations

from pathlib import Path

from onyx.security_layer.decisions.models import DecisionType, RiskLevel, SecurityDecision
from onyx.security_layer.policy.context import PolicyContext
from onyx.security_layer.policy.loader import load_policy_directory
from onyx.security_layer.policy.models import PolicyDefinition, PolicyMode
from onyx.security_layer.policy.rules import rule_matches


class PolicyEngine:
    def __init__(self, policies: list[PolicyDefinition]) -> None:
        self._policies = policies

    @classmethod
    def from_directory(cls, path: Path) -> "PolicyEngine":
        return cls(load_policy_directory(path))

    def evaluate(self, context: PolicyContext) -> SecurityDecision:
        matching_surface = [p for p in self._policies if p.surface in {None, context.resource_type, context.action.split(':')[0]}]
        for policy in matching_surface:
            for rule in policy.rules:
                if not rule_matches(rule, context):
                    continue
                decision_type = DecisionType(rule.decision.value if policy.mode in {PolicyMode.ENFORCE, PolicyMode.BLOCK} else DecisionType.ALLOW.value)
                return SecurityDecision(
                    decision=decision_type,
                    risk_level=RiskLevel(rule.risk_level),
                    reason=rule.reason or f"Matched rule {rule.id}",
                    policy_id=policy.policy_id,
                    matched_rules=[rule.id],
                    evidence={"mode": policy.mode.value, "policy_version": policy.policy_version, "surface": policy.surface or "unknown"},
                    subject_type=context.subject_type,
                    subject_id=context.subject_id,
                    tenant_id=context.tenant_id,
                    session_id=context.session_id,
                    resource_type=context.resource_type,
                    resource_id=context.resource_id,
                    action=context.action,
                )

        default_policy = matching_surface[0] if matching_surface else None
        default_decision = DecisionType.ALLOW if default_policy is None else DecisionType(default_policy.default_decision.value)
        return SecurityDecision(
            decision=default_decision,
            risk_level=RiskLevel.MEDIUM if default_decision != DecisionType.ALLOW else RiskLevel.LOW,
            reason="No matching policy rule found",
            policy_id=default_policy.policy_id if default_policy else "default",
            matched_rules=["default:no_match"],
            evidence={"policy_version": default_policy.policy_version if default_policy else "v1", "surface": default_policy.surface if default_policy else "unknown"},
            subject_type=context.subject_type,
            subject_id=context.subject_id,
            tenant_id=context.tenant_id,
            session_id=context.session_id,
            resource_type=context.resource_type,
            resource_id=context.resource_id,
            action=context.action,
        )
