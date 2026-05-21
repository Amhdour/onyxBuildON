from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from onyx.security_layer.redaction import redact_security_payload


@dataclass
class SecurityContext:
    actor_user_id: str | None = None
    tenant_id: str | None = None
    session_id: str | None = None
    correlation_id: str | None = None
    request_id: str | None = None
    surface: str | None = None
    action: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    tool_name: str | None = None
    mcp_server: str | None = None
    mcp_tool: str | None = None
    mcp_scope: str | None = None
    retrieval_document_id: str | None = None
    artifact_id: str | None = None
    launch_gate_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    missing_context: dict[str, bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.correlation_id:
            self.correlation_id = str(uuid4())
        self.missing_context = {
            "missing_user": (self.actor_user_id is None) or str(self.actor_user_id).startswith("missing:"),
            "missing_tenant": (self.tenant_id is None) or str(self.tenant_id).startswith("missing:"),
            "missing_session": (self.session_id is None) or str(self.session_id).startswith("missing:"),
        }

    def requires_user_context(self) -> bool:
        return self.surface in {"tool_execution", "mcp", "retrieval", "artifact", "sandbox"}

    def requires_tenant_context(self) -> bool:
        return self.surface in {"tool_execution", "mcp", "retrieval", "artifact", "sandbox"}

    def missing_required_context_reasons(self) -> list[str]:
        reasons: list[str] = []
        if self.requires_user_context() and self.missing_context["missing_user"]:
            reasons.append("missing_user_context")
        if self.requires_tenant_context() and self.missing_context["missing_tenant"]:
            reasons.append("missing_tenant_context")
        if self.missing_context["missing_session"]:
            reasons.append("missing_session_context")
        return reasons

    def has_required_context(self) -> bool:
        return len(self.missing_required_context_reasons()) == 0

    def to_policy_context(self) -> dict[str, Any]:
        return self.to_redacted_dict()

    def to_audit_metadata(self) -> dict[str, Any]:
        return {"missing_context": self.missing_context, "request_id": self.request_id, **self.metadata}

    def to_redacted_dict(self) -> dict[str, Any]:
        return redact_security_payload(self.__dict__)
