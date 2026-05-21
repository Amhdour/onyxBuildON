from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.decisions.models import RiskLevel
from onyx.security_layer.decisions.models import SecurityDecision


def test_security_decision_model() -> None:
    decision = SecurityDecision(
        decision=DecisionType.ALLOW,
        risk_level=RiskLevel.LOW,
        reason="ok",
        policy_id="p1",
        subject_type="user",
        subject_id="u1",
        tenant_id="t1",
        session_id="s1",
        resource_type="tool",
        resource_id="r1",
        action="read",
    )
    assert decision.decision == DecisionType.ALLOW
    assert decision.decision_id
