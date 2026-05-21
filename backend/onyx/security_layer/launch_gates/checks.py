from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class GateStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


@dataclass(frozen=True)
class LaunchGateCheck:
    gate: str
    status: GateStatus
    message: str
    is_blocking: bool = False


GATE_CATEGORIES = [
    "tool_authorization",
    "opencode_policy",
    "sandbox_security",
    "retrieval_acl_proof",
    "mcp_authorization",
    "artifact_security",
    "audit_coverage",
    "findings",
]

BLOCKING_FAILURES = {
    "high-risk tool allowed without decision",
    "OpenCode bash allowed broadly",
    "Docker socket exposed",
    "local sandbox in production",
    "unsafe sandbox base path in production",
    "unknown ACL allowed",
    "cross-tenant retrieval allowed",
    "MCP call allowed without scope",
    "artifact secret leak allowed",
    "audit disabled",
    "policy engine disabled",
}
