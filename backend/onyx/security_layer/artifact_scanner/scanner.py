from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.findings.models import FindingSeverity
from onyx.security_layer.findings.models import SecurityFinding
from onyx.security_layer.launch_gates.evidence import LaunchGateEvidence
from onyx.security_layer.artifact_scanner.html import scan_html_signals
from onyx.security_layer.artifact_scanner.html import scan_hidden_text_prompt_injection
from onyx.security_layer.artifact_scanner.pii import scan_pii_signals
from onyx.security_layer.artifact_scanner.provenance import scan_provenance_signals
from onyx.security_layer.artifact_scanner.secrets import scan_secret_signals


class ScanDecision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class ArtifactMetadata(BaseModel):
    artifact_id: str
    tenant_id: str
    user_id: str
    session_id: str
    artifact_type: str
    filename: str | None = None


class SecuritySignal(BaseModel):
    signal_type: str
    severity: str
    snippet: str


class ArtifactScanResult(BaseModel):
    decision: ScanDecision
    signals: list[SecuritySignal] = Field(default_factory=list)
    audit_events: list[AuditEvent] = Field(default_factory=list)
    finding: SecurityFinding | None = None
    launch_gate_evidence: LaunchGateEvidence


LARGE_EXCERPT_THRESHOLD = 3_000
HTML_LIKE_TYPES = {"html", "markdown"}


def scan_artifact(content: str, metadata: ArtifactMetadata) -> ArtifactScanResult:
    blocked_signals: list[SecuritySignal] = []
    warned_signals: list[SecuritySignal] = []

    for finding_type, snippet in scan_secret_signals(content):
        blocked_signals.append(SecuritySignal(signal_type=finding_type, severity="high", snippet=snippet))

    artifact_type = metadata.artifact_type.lower()

    html_blocked, html_warned = ([], [])
    if artifact_type in HTML_LIKE_TYPES:
        html_blocked, html_warned = scan_html_signals(content)

    for finding_type, snippet in html_blocked:
        blocked_signals.append(SecuritySignal(signal_type=finding_type, severity="high", snippet=snippet))
    for finding_type, snippet in html_warned:
        warned_signals.append(SecuritySignal(signal_type=finding_type, severity="medium", snippet=snippet))

    hidden_prompt_injection_signal = scan_hidden_text_prompt_injection(content)
    if hidden_prompt_injection_signal:
        finding_type, snippet = hidden_prompt_injection_signal
        blocked_signals.append(SecuritySignal(signal_type=finding_type, severity="high", snippet=snippet))

    for finding_type, snippet in scan_pii_signals(content):
        warned_signals.append(SecuritySignal(signal_type=finding_type, severity="medium", snippet=snippet))

    for finding_type, snippet in scan_provenance_signals(content):
        warned_signals.append(SecuritySignal(signal_type=finding_type, severity="low", snippet=snippet))

    if len(content) >= LARGE_EXCERPT_THRESHOLD:
        warned_signals.append(
            SecuritySignal(
                signal_type="large_document_excerpt",
                severity="medium",
                snippet=f"artifact length={len(content)}",
            )
        )

    decision = ScanDecision.ALLOW
    if blocked_signals:
        decision = ScanDecision.BLOCK
    elif warned_signals:
        decision = ScanDecision.WARN

    audit_events = [
        AuditEvent(
            event_type="artifact_scanned",
            tenant_id=metadata.tenant_id,
            user_id=metadata.user_id,
            session_id=metadata.session_id,
            decision_id=f"scan:{metadata.artifact_id}",
            resource_type="artifact",
            resource_id=metadata.artifact_id,
            action="scan",
            risk_level="high" if blocked_signals else "medium" if warned_signals else "low",
            details={"artifact_type": metadata.artifact_type, "decision": decision.value},
        )
    ]

    finding: SecurityFinding | None = None
    if decision == ScanDecision.BLOCK:
        audit_events.append(
            AuditEvent(
                event_type="artifact_blocked",
                tenant_id=metadata.tenant_id,
                user_id=metadata.user_id,
                session_id=metadata.session_id,
                decision_id=f"scan:{metadata.artifact_id}",
                resource_type="artifact",
                resource_id=metadata.artifact_id,
                action="block",
                risk_level="high",
                details={"signals": ",".join(signal.signal_type for signal in blocked_signals)},
            )
        )
        finding = SecurityFinding(
            title=f"Blocked artifact {metadata.artifact_id}",
            category="artifact_scan",
            severity=FindingSeverity.HIGH,
            tenant_id=metadata.tenant_id,
            asset_type="artifact",
            asset_id=metadata.artifact_id,
            policy_id="artifact_scanner_mvp",
            evidence={"signals": ",".join(signal.signal_type for signal in blocked_signals)},
            recommended_fix="Remove secrets/malicious payloads and resubmit artifact",
            blocking_launch=True,
        )

    all_signals = blocked_signals + warned_signals
    evidence = LaunchGateEvidence(
        audit_evidence_sample=[
            {
                "event_type": "artifact_scanned",
                "artifact_id": metadata.artifact_id,
                "decision": decision.value,
            }
        ],
        policy_decisions=[
            {
                "policy_id": "artifact_scanner_mvp",
                "decision": decision.value,
                "artifact_type": metadata.artifact_type,
                "signal_count": len(all_signals),
            }
        ],
    )

    return ArtifactScanResult(
        decision=decision,
        signals=all_signals,
        audit_events=audit_events,
        finding=finding,
        launch_gate_evidence=evidence,
    )
