from pathlib import Path

from onyx.security_layer.models import DecisionOutcome
from onyx.security_layer.models import PolicyMode
from onyx.security_layer.policy_engine import YamlPolicyEngine
from onyx.security_layer.runtime import SecurityRuntime
from onyx.security_layer.runtime import artifact_scanner
from onyx.security_layer.runtime import launch_gate_report
from onyx.security_layer.runtime import mcp_scope_authorization
from onyx.security_layer.runtime import opencode_restrictions
from onyx.security_layer.runtime import retrieval_acl_proof
from onyx.security_layer.runtime import sandbox_launch_gate
from onyx.security_layer.runtime import tool_authorization_gate


def test_yaml_policy_engine_modes(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("rules:\n  - name: deny_sandbox\n    action: sandbox:launch\n    outcome: deny\n")

    warn_engine = YamlPolicyEngine(policy_file, mode=PolicyMode.WARN)
    warn_decision = warn_engine.evaluate("sandbox:launch", "user_1", {})
    assert warn_decision.outcome == DecisionOutcome.WARN

    enforce_engine = YamlPolicyEngine(policy_file, mode=PolicyMode.ENFORCE)
    enforce_decision = enforce_engine.evaluate("sandbox:launch", "user_1", {})
    assert enforce_decision.outcome == DecisionOutcome.DENY


def test_runtime_disabled_defaults_to_allow() -> None:
    runtime = SecurityRuntime(engine=YamlPolicyEngine(mode=PolicyMode.BLOCK), enabled=False)
    result = runtime.authorize("tool:write", "user_1", {"secret_token": "abc"})
    assert result.decision.outcome == DecisionOutcome.ALLOW
    assert result.audit_event.details["secret_token"] == "[REDACTED]"


def test_runtime_controls_generate_decisions_and_reports() -> None:
    runtime = SecurityRuntime(engine=YamlPolicyEngine(mode=PolicyMode.OBSERVE), enabled=True)

    controls = [
        tool_authorization_gate(runtime, "terminal", "user_1"),
        opencode_restrictions(runtime, "user_1", "/etc/passwd"),
        sandbox_launch_gate(runtime, "user_1", "unsafe-image"),
        retrieval_acl_proof(runtime, "user_1", "doc-1", acl_ok=False),
        mcp_scope_authorization(runtime, "user_1", "admin:all"),
        artifact_scanner(runtime, "user_1", "artifact.txt", "BEGIN PRIVATE KEY"),
    ]

    for result in controls:
        report = launch_gate_report(result)
        assert report["action"]
        assert report["mode"] == "observe"
