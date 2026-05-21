from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.sandbox_guard import SandboxPolicy
from onyx.security_layer.sandbox_guard import run_sandbox_launch_gate


def _run(overrides: dict[str, str | bool | None], policy: SandboxPolicy | None = None):
    return run_sandbox_launch_gate(
        user_id="user-1",
        tenant_id="tenant-1",
        session_id="session-1",
        environment="production",
        policy=policy,
        overrides=overrides,
    )


def test_local_sandbox_in_production_fails() -> None:
    result = _run({"sandbox_backend": "local"})
    assert result.outcome == DecisionType.DENY


def test_docker_socket_exposed_fails() -> None:
    result = _run({"sandbox_docker_socket": "/var/run/docker.sock", "strict_isolation_enabled": False})
    assert result.outcome == DecisionType.DENY


def test_tmp_sandbox_base_path_fails_in_production() -> None:
    result = _run({"sandbox_base_path": "/tmp/onyx-sandboxes"})
    assert result.outcome == DecisionType.DENY


def test_missing_resource_limits_fail_or_warn_by_policy() -> None:
    fail_policy = SandboxPolicy(
        fail_on_missing_cpu_limit=True,
        fail_on_missing_memory_limit=True,
        fail_on_missing_disk_limit=True,
    )
    fail_result = _run({"cpu_limit": None, "memory_limit": None, "disk_limit": None}, policy=fail_policy)
    assert fail_result.outcome == DecisionType.DENY

    warn_policy = SandboxPolicy(
        fail_on_missing_cpu_limit=False,
        fail_on_missing_memory_limit=False,
        fail_on_missing_disk_limit=False,
    )
    warn_result = _run({"cpu_limit": None, "memory_limit": None, "disk_limit": None}, policy=warn_policy)
    assert any(check.level.value == "warning" for check in warn_result.checks)


def test_privileged_container_fails() -> None:
    result = _run({"privileged_containers_enabled": True})
    assert result.outcome == DecisionType.DENY


def test_cleanup_disabled_fails_or_warns() -> None:
    fail_result = _run({"cleanup_enabled": False}, policy=SandboxPolicy(fail_on_cleanup_disabled=True))
    assert fail_result.outcome == DecisionType.DENY

    warn_result = _run({"cleanup_enabled": False}, policy=SandboxPolicy(fail_on_cleanup_disabled=False))
    assert any(check.check_id == "cleanup_disabled" and check.level.value == "warning" for check in warn_result.checks)


def test_network_policy_missing_warns_or_fails() -> None:
    warn_result = _run({"network_policy_enabled": False}, policy=SandboxPolicy(fail_on_missing_network_policy=False))
    assert any(check.check_id == "network_policy_missing" and check.level.value == "warning" for check in warn_result.checks)

    fail_result = _run({"network_policy_enabled": False}, policy=SandboxPolicy(fail_on_missing_network_policy=True))
    assert fail_result.outcome == DecisionType.DENY


def test_findings_created_for_blocking_failures() -> None:
    result = _run({"sandbox_backend": "local", "sandbox_docker_socket": "/var/run/docker.sock"})
    assert result.findings
    assert any(f.policy_id == "local_backend_in_production" for f in result.findings)
    assert any(f.policy_id == "docker_socket_exposure" for f in result.findings)


def test_audit_events_created_for_failures() -> None:
    result = _run({"sandbox_backend": "local"})
    assert result.audit_events
    assert result.audit_events[0].event_type == "sandbox_gate_failed"
