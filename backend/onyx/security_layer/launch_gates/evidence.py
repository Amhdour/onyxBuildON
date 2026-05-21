from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LaunchGateEvidence:
    audit_evidence_sample: list[dict[str, object]] = field(default_factory=list)
    policy_decisions: list[dict[str, object]] = field(default_factory=list)
