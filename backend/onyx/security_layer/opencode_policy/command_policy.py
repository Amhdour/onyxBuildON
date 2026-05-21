from __future__ import annotations

from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.findings.models import FindingSeverity
from onyx.security_layer.findings.models import SecurityFinding
from onyx.security_layer.findings.service import FindingService

CRITICAL_PATTERNS = ("docker", "kubectl", "terraform apply", "printenv", " env ")
DENIED_PATTERNS = (
    "sudo",
    "chmod",
    "chown",
    "docker",
    "kubectl",
    "terraform apply",
    "git push",
    "scp",
    "rsync",
    "printenv",
    " env ",
    "cat ~/.ssh/",
    "cat ~/.aws/",
    "cat ~/.config/",
    "cat /etc/passwd",
)


def maybe_record_command_violation(
    command: str,
    *,
    audit_service: AuditService | None = None,
    finding_service: FindingService | None = None,
) -> None:
    normalized = f" {command.strip().lower()} "
    matched = next((pattern for pattern in DENIED_PATTERNS if pattern in normalized), None)
    if not matched:
        return

    critical = matched in CRITICAL_PATTERNS
    if audit_service:
        audit_service.record(
            AuditEvent(
                event_type="opencode_command_policy",
                tenant_id="sandbox",
                user_id="opencode",
                session_id="unknown",
                decision_id="opencode-policy",
                resource_type="command",
                resource_id=command,
                action="deny",
                risk_level="critical" if critical else "high",
                details={"matched_pattern": matched},
            )
        )

    if finding_service and critical:
        finding_service.create(
            SecurityFinding(
                title=f"Denied critical OpenCode command: {matched}",
                category="opencode_policy",
                severity=FindingSeverity.CRITICAL,
                tenant_id="sandbox",
                asset_type="command",
                asset_id=command,
                policy_id="opencode_policy",
                evidence={"matched_pattern": matched},
                recommended_fix="Remove dangerous command from planned execution",
            )
        )
