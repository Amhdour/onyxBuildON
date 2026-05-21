from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CheckLevel(str, Enum):
    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"


@dataclass(frozen=True)
class SandboxCheckResult:
    check_id: str
    level: CheckLevel
    message: str


@dataclass(frozen=True)
class SandboxPolicy:
    fail_on_missing_cpu_limit: bool = True
    fail_on_missing_memory_limit: bool = True
    fail_on_missing_disk_limit: bool = False
    fail_on_cleanup_disabled: bool = False
    fail_on_missing_network_policy: bool = False
    fail_on_missing_object_store_encryption: bool = False


def policy_level(policy_should_fail: bool) -> CheckLevel:
    return CheckLevel.FAIL if policy_should_fail else CheckLevel.WARNING
