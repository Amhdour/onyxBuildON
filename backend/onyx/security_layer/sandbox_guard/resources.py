from __future__ import annotations

from onyx.security_layer.sandbox_guard.checks import CheckLevel
from onyx.security_layer.sandbox_guard.checks import SandboxCheckResult
from onyx.security_layer.sandbox_guard.checks import SandboxPolicy
from onyx.security_layer.sandbox_guard.checks import policy_level


def check_cpu_limit(cpu_limit: str | None, policy: SandboxPolicy) -> SandboxCheckResult:
    if not cpu_limit:
        return SandboxCheckResult(
            check_id="cpu_limit_missing",
            level=policy_level(policy.fail_on_missing_cpu_limit),
            message="Sandbox CPU limit is missing",
        )
    return SandboxCheckResult("cpu_limit_missing", CheckLevel.PASS, "Sandbox CPU limit is set")


def check_memory_limit(memory_limit: str | None, policy: SandboxPolicy) -> SandboxCheckResult:
    if not memory_limit:
        return SandboxCheckResult(
            check_id="memory_limit_missing",
            level=policy_level(policy.fail_on_missing_memory_limit),
            message="Sandbox memory limit is missing",
        )
    return SandboxCheckResult("memory_limit_missing", CheckLevel.PASS, "Sandbox memory limit is set")


def check_disk_limit(disk_limit: str | None, policy: SandboxPolicy) -> SandboxCheckResult:
    if not disk_limit:
        return SandboxCheckResult(
            check_id="disk_limit_missing",
            level=policy_level(policy.fail_on_missing_disk_limit),
            message="Sandbox disk limit is missing",
        )
    return SandboxCheckResult("disk_limit_missing", CheckLevel.PASS, "Sandbox disk limit is set")


def check_cleanup_enabled(cleanup_enabled: bool, policy: SandboxPolicy) -> SandboxCheckResult:
    if not cleanup_enabled:
        return SandboxCheckResult(
            check_id="cleanup_disabled",
            level=policy_level(policy.fail_on_cleanup_disabled),
            message="Sandbox cleanup is disabled",
        )
    return SandboxCheckResult("cleanup_disabled", CheckLevel.PASS, "Sandbox cleanup is enabled")


def check_object_store_encryption(
    object_store_encryption_enabled: bool, policy: SandboxPolicy
) -> SandboxCheckResult:
    if not object_store_encryption_enabled:
        return SandboxCheckResult(
            check_id="object_store_encryption_missing",
            level=policy_level(policy.fail_on_missing_object_store_encryption),
            message="Sandbox object-store encryption is missing",
        )
    return SandboxCheckResult(
        "object_store_encryption_missing", CheckLevel.PASS, "Sandbox object-store encryption is enabled"
    )
