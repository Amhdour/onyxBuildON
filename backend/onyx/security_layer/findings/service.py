from __future__ import annotations

from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.decisions.models import SecurityDecision
from onyx.security_layer.findings.models import FindingSeverity
from onyx.security_layer.findings.models import SecurityFinding


class FindingService:
    def __init__(self) -> None:
        self._findings: list[SecurityFinding] = []

    def create(self, finding: SecurityFinding) -> SecurityFinding:
        self._findings.append(finding)
        return finding

    def create_from_decision(self, decision: SecurityDecision) -> SecurityFinding | None:
        if decision.decision == DecisionType.ALLOW and decision.risk_level.value in {"low", "medium"}:
            return None
        finding = SecurityFinding(
            title=f"Risky action: {decision.action}",
            category="policy_violation",
            severity=FindingSeverity(decision.risk_level.value),
            tenant_id=decision.tenant_id,
            asset_type=decision.resource_type,
            asset_id=decision.resource_id,
            policy_id=decision.policy_id,
            evidence=decision.evidence,
            recommended_fix="Review policy and reduce risk before launch",
            blocking_launch=decision.risk_level.value in {"high", "critical"},
        )
        self._findings.append(finding)
        return finding

    def list_all(self) -> list[SecurityFinding]:
        return list(self._findings)
