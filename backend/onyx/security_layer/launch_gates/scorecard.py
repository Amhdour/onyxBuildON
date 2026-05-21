from __future__ import annotations

from dataclasses import dataclass

from onyx.security_layer.launch_gates.checks import GateStatus
from onyx.security_layer.launch_gates.checks import LaunchGateCheck


@dataclass(frozen=True)
class LaunchGateScorecard:
    checks: list[LaunchGateCheck]

    @property
    def passed_gates(self) -> list[str]:
        return [c.gate for c in self.checks if c.status == GateStatus.PASS]

    @property
    def failed_gates(self) -> list[str]:
        return [c.gate for c in self.checks if c.status == GateStatus.FAIL]

    @property
    def warnings(self) -> list[str]:
        return [c.gate for c in self.checks if c.status == GateStatus.WARNING]

    @property
    def overall_status(self) -> GateStatus:
        if any(c.status == GateStatus.FAIL and c.is_blocking for c in self.checks):
            return GateStatus.FAIL
        if any(c.status == GateStatus.FAIL for c in self.checks):
            return GateStatus.WARNING
        if any(c.status in {GateStatus.WARNING, GateStatus.MANUAL_REVIEW_REQUIRED} for c in self.checks):
            return GateStatus.WARNING
        return GateStatus.PASS
