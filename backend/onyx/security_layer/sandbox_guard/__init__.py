from __future__ import annotations

from dataclasses import dataclass

from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.findings.models import FindingSeverity
from onyx.security_layer.findings.models import SecurityFinding
from onyx.security_layer.findings.service import FindingService
from onyx.security_layer.sandbox_guard.checks import CheckLevel
from onyx.security_layer.sandbox_guard.checks import SandboxCheckResult
from onyx.security_layer.sandbox_guard.checks import SandboxPolicy
from onyx.security_layer.sandbox_guard.docker import check_docker_socket_exposure
from onyx.security_layer.sandbox_guard.docker import check_privileged_containers
from onyx.security_layer.sandbox_guard.filesystem import check_sandbox_base_path
from onyx.security_layer.sandbox_guard.kubernetes import check_network_policy_present
from onyx.security_layer.sandbox_guard.resources import check_cleanup_enabled
from onyx.security_layer.sandbox_guard.resources import check_cpu_limit
from onyx.security_layer.sandbox_guard.resources import check_disk_limit
from onyx.security_layer.sandbox_guard.resources import check_memory_limit
from onyx.security_layer.sandbox_guard.resources import check_object_store_encryption
from onyx.server.features.build.configs import SANDBOX_BACKEND
from onyx.server.features.build.configs import SANDBOX_BASE_PATH
from onyx.server.features.build.configs import SANDBOX_DOCKER_CPU_LIMIT
from onyx.server.features.build.configs import SANDBOX_DOCKER_MEMORY_LIMIT
from onyx.server.features.build.configs import SANDBOX_DOCKER_SOCKET
from onyx.server.features.build.configs import SandboxBackend


@dataclass(frozen=True)
class SandboxGateResult:
    outcome: DecisionType
    checks: list[SandboxCheckResult]
    audit_events: list[AuditEvent]
    findings: list[SecurityFinding]


def _is_production(environment: str) -> bool:
    return environment.lower() in {"prod", "production"}


def run_sandbox_launch_gate(
    *,
    user_id: str,
    tenant_id: str,
    session_id: str,
    environment: str,
    policy: SandboxPolicy | None = None,
    audit_service: AuditService | None = None,
    finding_service: FindingService | None = None,
    overrides: dict[str, str | bool | None] | None = None,
) -> SandboxGateResult:
    active_policy = policy or SandboxPolicy()
    data = overrides or {}
    in_production = _is_production(environment)

    backend_value = str(data.get("sandbox_backend", SANDBOX_BACKEND.value))
    docker_socket = str(data.get("sandbox_docker_socket", SANDBOX_DOCKER_SOCKET))
    strict_isolation = bool(data.get("strict_isolation_enabled", False))
    base_path = str(data.get("sandbox_base_path", SANDBOX_BASE_PATH))
    privileged_enabled = bool(data.get("privileged_containers_enabled", False))
    cpu_limit = data.get("cpu_limit")
    if cpu_limit is None:
        cpu_limit = str(SANDBOX_DOCKER_CPU_LIMIT) if SANDBOX_DOCKER_CPU_LIMIT else None
    memory_limit = data.get("memory_limit")
    if memory_limit is None:
        memory_limit = SANDBOX_DOCKER_MEMORY_LIMIT
    disk_limit = data.get("disk_limit")
    cleanup_enabled = bool(data.get("cleanup_enabled", True))
    network_policy_enabled = bool(data.get("network_policy_enabled", True))
    object_store_encryption_enabled = bool(data.get("object_store_encryption_enabled", True))

    checks: list[SandboxCheckResult] = []

    if in_production and backend_value == SandboxBackend.LOCAL.value:
        checks.append(SandboxCheckResult("local_backend_in_production", CheckLevel.FAIL, "Local sandbox backend is not allowed in production"))
    else:
        checks.append(SandboxCheckResult("local_backend_in_production", CheckLevel.PASS, "Sandbox backend passes production guard"))

    checks.append(check_docker_socket_exposure(docker_socket, strict_isolation))
    checks.append(check_sandbox_base_path(base_path, in_production))
    checks.append(check_privileged_containers(privileged_enabled))
    checks.append(check_cpu_limit(cpu_limit, active_policy))
    checks.append(check_memory_limit(memory_limit, active_policy))
    checks.append(check_disk_limit(disk_limit if isinstance(disk_limit, str) else None, active_policy))
    checks.append(check_cleanup_enabled(cleanup_enabled, active_policy))
    checks.append(check_network_policy_present(network_policy_enabled, active_policy))
    checks.append(check_object_store_encryption(object_store_encryption_enabled, active_policy))

    failed_checks = [check for check in checks if check.level == CheckLevel.FAIL]
    outcome = DecisionType.DENY if failed_checks else DecisionType.ALLOW

    audit = audit_service or AuditService()
    findings_service = finding_service or FindingService()

    event_type = "sandbox_gate_failed" if failed_checks else "sandbox_gate_passed"
    audit_event = audit.record(
        AuditEvent(
            event_type=event_type,
            tenant_id=tenant_id,
            user_id=user_id,
            session_id=session_id,
            decision_id="sandbox-launch-gate",
            resource_type="sandbox",
            resource_id=session_id,
            action="launch",
            risk_level="critical" if failed_checks else "low",
            details={
                "environment": environment,
                "failed_checks": ",".join(c.check_id for c in failed_checks),
            },
        )
    )

    findings: list[SecurityFinding] = []
    for check in failed_checks:
        if check.check_id == "docker_socket_exposure":
            severity = FindingSeverity.CRITICAL
        elif check.check_id == "local_backend_in_production":
            severity = FindingSeverity.CRITICAL
        elif check.check_id == "unsafe_base_path":
            severity = FindingSeverity.CRITICAL if in_production else FindingSeverity.HIGH
        elif check.check_id in {"cpu_limit_missing", "memory_limit_missing", "disk_limit_missing"}:
            severity = FindingSeverity.HIGH
        else:
            severity = FindingSeverity.HIGH

        findings.append(
            findings_service.create(
                SecurityFinding(
                    title=f"Sandbox launch gate failed: {check.check_id}",
                    category="sandbox_launch_gate",
                    severity=severity,
                    tenant_id=tenant_id,
                    asset_type="sandbox",
                    asset_id=session_id,
                    policy_id=check.check_id,
                    evidence={"message": check.message, "environment": environment},
                    recommended_fix="Harden sandbox launch configuration before deployment",
                    blocking_launch=True,
                )
            )
        )

    return SandboxGateResult(outcome=outcome, checks=checks, audit_events=[audit_event], findings=findings)


__all__ = ["SandboxGateResult", "SandboxPolicy", "run_sandbox_launch_gate"]
