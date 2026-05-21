from __future__ import annotations

from onyx.security_layer.sandbox_guard.checks import CheckLevel
from onyx.security_layer.sandbox_guard.checks import SandboxCheckResult


def check_docker_socket_exposure(
    docker_socket: str,
    strict_isolation_enabled: bool,
) -> SandboxCheckResult:
    if docker_socket == "/var/run/docker.sock" and not strict_isolation_enabled:
        return SandboxCheckResult(
            check_id="docker_socket_exposure",
            level=CheckLevel.FAIL,
            message="Docker socket exposed without strict isolation",
        )

    return SandboxCheckResult(
        check_id="docker_socket_exposure",
        level=CheckLevel.PASS,
        message="Docker socket configuration passes guard",
    )


def check_privileged_containers(privileged_enabled: bool) -> SandboxCheckResult:
    if privileged_enabled:
        return SandboxCheckResult(
            check_id="privileged_containers",
            level=CheckLevel.FAIL,
            message="Privileged containers are enabled",
        )

    return SandboxCheckResult(
        check_id="privileged_containers",
        level=CheckLevel.PASS,
        message="Privileged containers are disabled",
    )
