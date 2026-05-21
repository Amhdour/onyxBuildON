from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class PolicyMode(str, Enum):
    OBSERVE = "observe"
    WARN = "warn"
    ENFORCE = "enforce"
    BLOCK = "block"


class RuleDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class PolicyRule(BaseModel):
    id: str
    description: str = ""
    condition: dict[str, str | list[str] | int | bool] = Field(default_factory=dict)
    decision: RuleDecision
    risk_level: str = "low"
    reason: str = ""


class PolicyDefinition(BaseModel):
    policy_id: str
    mode: PolicyMode = PolicyMode.OBSERVE
    rules: list[PolicyRule] = Field(default_factory=list)
