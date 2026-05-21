from __future__ import annotations

from dataclasses import dataclass

from onyx.security_layer.models import AuditEvent
from onyx.security_layer.models import DecisionOutcome
from onyx.security_layer.models import FindingSeverity
from onyx.security_layer.models import SecurityDecision
from onyx.security_layer.models import SecurityFinding
from onyx.security_layer.policy_engine import YamlPolicyEngine


@dataclass
class SecurityRuntimeResult:
    decision: SecurityDecision
    audit_event: AuditEvent
    finding: SecurityFinding | None


class SecurityRuntime:
    def __init__(self, engine: YamlPolicyEngine, enabled: bool = False) -> None:
        self.engine = engine
        self.enabled = enabled

    def authorize(self, action: str, actor_id: str, context: dict[str, str]) -> SecurityRuntimeResult:
        if not self.enabled:
            decision = SecurityDecision(
                action=action,
                actor_id=actor_id,
                mode=self.engine.mode,
                outcome=DecisionOutcome.ALLOW,
                explainability=["security_layer_disabled"],
            )
        else:
            decision = self.engine.evaluate(action=action, actor_id=actor_id, context=context)

        audit = AuditEvent(
            action=action,
            actor_id=actor_id,
            details={k: ("[REDACTED]" if "secret" in k.lower() else v) for k, v in context.items()},
            redactions_applied=any("secret" in k.lower() for k in context),
        )
        finding = None
        if decision.outcome in [DecisionOutcome.WARN, DecisionOutcome.DENY]:
            finding = SecurityFinding(
                category="runtime_authorization",
                action=action,
                actor_id=actor_id,
                severity=FindingSeverity.HIGH if decision.outcome == DecisionOutcome.DENY else FindingSeverity.MEDIUM,
                rationale=", ".join(decision.explainability) or "policy_match",
            )

        return SecurityRuntimeResult(decision=decision, audit_event=audit, finding=finding)


def tool_authorization_gate(runtime: SecurityRuntime, tool_name: str, actor_id: str) -> SecurityRuntimeResult:
    return runtime.authorize(action=f"tool:{tool_name}", actor_id=actor_id, context={"tool": tool_name})


def opencode_restrictions(runtime: SecurityRuntime, actor_id: str, requested_path: str) -> SecurityRuntimeResult:
    sensitive = "true" if requested_path.startswith("/etc") else "false"
    return runtime.authorize(
        action="opencode:filesystem_access",
        actor_id=actor_id,
        context={"path": requested_path, "sensitive": sensitive},
    )


def sandbox_launch_gate(runtime: SecurityRuntime, actor_id: str, image: str) -> SecurityRuntimeResult:
    return runtime.authorize(action="sandbox:launch", actor_id=actor_id, context={"image": image})


def retrieval_acl_proof(runtime: SecurityRuntime, actor_id: str, document_id: str, acl_ok: bool) -> SecurityRuntimeResult:
    return runtime.authorize(
        action="retrieval:read",
        actor_id=actor_id,
        context={"document_id": document_id, "acl": "pass" if acl_ok else "fail"},
    )


def mcp_scope_authorization(runtime: SecurityRuntime, actor_id: str, scope: str) -> SecurityRuntimeResult:
    return runtime.authorize(action="mcp:scope", actor_id=actor_id, context={"scope": scope})


def artifact_scanner(runtime: SecurityRuntime, actor_id: str, artifact_name: str, contents: str) -> SecurityRuntimeResult:
    suspicious = "true" if "AKIA" in contents or "BEGIN PRIVATE KEY" in contents else "false"
    return runtime.authorize(
        action="artifact:scan",
        actor_id=actor_id,
        context={"artifact": artifact_name, "sensitive": suspicious},
    )


def launch_gate_report(result: SecurityRuntimeResult) -> dict[str, str]:
    return {
        "action": result.decision.action,
        "outcome": result.decision.outcome.value,
        "mode": result.decision.mode.value,
        "explainability": " | ".join(result.decision.explainability),
        "audit_redacted": str(result.audit_event.redactions_applied),
    }
