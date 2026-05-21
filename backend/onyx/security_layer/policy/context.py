from __future__ import annotations

from pydantic import BaseModel, Field


class PolicyContext(BaseModel):
    tenant_id: str
    session_id: str
    subject_type: str
    subject_id: str
    resource_type: str
    resource_id: str
    action: str
    metadata: dict[str, str | int | bool | list[str]] = Field(default_factory=dict)
