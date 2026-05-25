from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class SecurityFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    category: str
    severity: FindingSeverity
    status: FindingStatus = FindingStatus.OPEN
    tenant_id: str | None
    asset_type: str
    asset_id: str
    policy_id: str
    evidence: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    recommended_fix: str
    blocking_launch: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
