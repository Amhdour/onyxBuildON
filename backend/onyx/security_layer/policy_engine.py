from __future__ import annotations

from pathlib import Path
import yaml

from onyx.security_layer.models import DecisionOutcome
from onyx.security_layer.models import PolicyMode
from onyx.security_layer.models import SecurityDecision


class YamlPolicyEngine:
    def __init__(self, policy_path: Path | None = None, mode: PolicyMode = PolicyMode.OBSERVE) -> None:
        self._policy = {"rules": []}
        self.mode = mode
        if policy_path:
            self._policy = yaml.safe_load(policy_path.read_text()) or {"rules": []}

    def evaluate(self, action: str, actor_id: str, context: dict[str, str]) -> SecurityDecision:
        matched = [rule for rule in self._policy.get("rules", []) if rule.get("action") == action]
        explainability = [f"rule:{rule.get('name', 'unnamed')}" for rule in matched]
        evidence = {"mode": self.mode.value, "matched_rules": str(len(matched))}
        requested = matched[0].get("outcome", DecisionOutcome.ALLOW.value) if matched else DecisionOutcome.ALLOW.value

        if self.mode == PolicyMode.OBSERVE:
            outcome = DecisionOutcome.ALLOW
            explainability.append("observe_mode_non_blocking")
        elif self.mode == PolicyMode.WARN and requested == DecisionOutcome.DENY.value:
            outcome = DecisionOutcome.WARN
            explainability.append("warn_mode_downgraded_from_deny")
        elif self.mode == PolicyMode.ENFORCE:
            outcome = DecisionOutcome(requested)
        elif self.mode == PolicyMode.BLOCK:
            outcome = DecisionOutcome.DENY
            explainability.append("global_block_mode")
        else:
            outcome = DecisionOutcome(requested)

        if context.get("sensitive") == "true":
            evidence["sensitive"] = "redacted"

        return SecurityDecision(
            action=action,
            actor_id=actor_id,
            mode=self.mode,
            outcome=outcome,
            explainability=explainability,
            evidence=evidence,
        )
