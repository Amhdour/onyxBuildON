from pathlib import Path

from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.policy.context import PolicyContext
from onyx.security_layer.policy.engine import PolicyEngine
from onyx.security_layer.policy.loader import load_policy_directory


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


def test_policy_yaml_directory_loads_and_validates() -> None:
    policy_path = Path("backend/onyx/security_layer/policies")
    policies = load_policy_directory(policy_path)
    assert len(policies) == 8
    assert all(policy.policy_id for policy in policies)


def test_policy_engine_defaults_to_allow_without_matching_rules() -> None:
    engine = PolicyEngine.from_directory(Path("backend/onyx/security_layer/policies"))
    result = engine.evaluate(_ctx("read", "doc"))
    assert result.decision == DecisionType.ALLOW
