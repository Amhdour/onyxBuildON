from __future__ import annotations

from dataclasses import dataclass

from onyx.security_layer.launch_gates.checks import GateStatus
from onyx.security_layer.launch_gates.checks import LaunchGateCheck
from onyx.security_layer.launch_gates.evidence import LaunchGateEvidence
from onyx.security_layer.launch_gates.scorecard import LaunchGateScorecard


@dataclass(frozen=True)
class LaunchGateInput:
    checks: list[LaunchGateCheck]
    findings: list[dict[str, object]]
    evidence: LaunchGateEvidence


@dataclass(frozen=True)
class LaunchGateResult:
    scorecard: LaunchGateScorecard
    findings: list[dict[str, object]]
    blocking_failures: list[str]
    evidence: LaunchGateEvidence

    @property
    def launch_blocked(self) -> bool:
        return self.scorecard.overall_status == GateStatus.FAIL


def evaluate_launch_gates(data: LaunchGateInput) -> LaunchGateResult:
    blocking_failures = [c.message for c in data.checks if c.status == GateStatus.FAIL and c.is_blocking]
    return LaunchGateResult(
        scorecard=LaunchGateScorecard(checks=data.checks),
        findings=data.findings,
        blocking_failures=blocking_failures,
        evidence=data.evidence,
    )
