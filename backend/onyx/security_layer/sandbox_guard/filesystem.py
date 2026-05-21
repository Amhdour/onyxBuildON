from __future__ import annotations

from onyx.security_layer.sandbox_guard.checks import CheckLevel
from onyx.security_layer.sandbox_guard.checks import SandboxCheckResult


def check_sandbox_base_path(base_path: str, in_production: bool) -> SandboxCheckResult:
    if in_production and base_path == "/tmp/onyx-sandboxes":
        return SandboxCheckResult(
            check_id="unsafe_base_path",
            level=CheckLevel.FAIL,
            message="Sandbox base path points to /tmp in production",
        )

    return SandboxCheckResult(
        check_id="unsafe_base_path",
        level=CheckLevel.PASS,
        message="Sandbox base path passes guard",
    )
