from onyx.security_layer.decisions.models import DecisionType, RiskLevel, SecurityDecision
from onyx.security_layer.findings.service import FindingService


def test_create_finding_from_risky_decision() -> None:
    service = FindingService()
    decision = SecurityDecision(
        decision=DecisionType.DENY,
        risk_level=RiskLevel.HIGH,
        reason="risky",
        policy_id="p1",
        subject_type="user",
        subject_id="u1",
        tenant_id="t1",
        session_id="s1",
        resource_type="artifact",
        resource_id="a1",
        action="delete",
    )
    finding = service.create_from_decision(decision)
    assert finding is not None
    assert finding.blocking_launch is True
