from __future__ import annotations

from onyx.security_layer.policy.context import PolicyContext
from onyx.security_layer.policy.models import PolicyRule


def rule_matches(rule: PolicyRule, context: PolicyContext) -> bool:
    for key, expected in rule.condition.items():
        actual = getattr(context, key, context.metadata.get(key))
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True
