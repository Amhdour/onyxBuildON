from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class DecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    decision: DecisionType
    risk_level: RiskLevel
    reason: str
    policy_id: str
    matched_rules: list[str] = Field(default_factory=list)
    evidence: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    subject_type: str
    subject_id: str
    tenant_id: str
    session_id: str
    resource_type: str
    resource_id: str
    action: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
