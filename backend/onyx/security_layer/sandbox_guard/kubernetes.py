from __future__ import annotations

from onyx.security_layer.sandbox_guard.checks import CheckLevel
from onyx.security_layer.sandbox_guard.checks import SandboxCheckResult
from onyx.security_layer.sandbox_guard.checks import SandboxPolicy
from onyx.security_layer.sandbox_guard.checks import policy_level


def check_network_policy_present(network_policy_enabled: bool, policy: SandboxPolicy) -> SandboxCheckResult:
    if not network_policy_enabled:
        level = policy_level(policy.fail_on_missing_network_policy)
        return SandboxCheckResult(
            check_id="network_policy_missing",
            level=level,
            message="Sandbox network policy is missing",
        )

    return SandboxCheckResult(
        check_id="network_policy_missing",
        level=CheckLevel.PASS,
        message="Sandbox network policy is present",
    )
