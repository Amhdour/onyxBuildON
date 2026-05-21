from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from pydantic import BaseModel, Field


class PolicyMode(str, Enum):
    OBSERVE = "observe"
    WARN = "warn"
    ENFORCE = "enforce"
    BLOCK = "block"


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"


class SecurityDecision(BaseModel):
    action: str
    actor_id: str
    mode: PolicyMode
    outcome: DecisionOutcome
    explainability: list[str] = Field(default_factory=list)
    evidence: dict[str, str] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditEvent(BaseModel):
    action: str
    actor_id: str
    details: dict[str, str] = Field(default_factory=dict)
    redactions_applied: bool = True
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class FindingSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityFinding(BaseModel):
    category: str
    action: str
    actor_id: str
    severity: FindingSeverity
    rationale: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
