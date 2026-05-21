from pathlib import Path

from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.policy.context import PolicyContext
from onyx.security_layer.policy.engine import PolicyEngine


def _ctx(action: str, resource_type: str) -> PolicyContext:
    return PolicyContext(
        tenant_id="t1",
        session_id="s1",
        subject_type="user",
        subject_id="u1",
        resource_type=resource_type,
        resource_id="r1",
        action=action,
    )


def test_policy_engine_decisions() -> None:
    engine = PolicyEngine.from_directory(Path("backend/onyx/security_layer/policies"))
    deny = engine.evaluate(_ctx("delete", "production"))
    assert deny.decision == DecisionType.DENY
    approve = engine.evaluate(_ctx("execute", "shell"))
    assert approve.decision == DecisionType.REQUIRE_APPROVAL
    allow = engine.evaluate(_ctx("read", "doc"))
    assert allow.decision == DecisionType.ALLOW
