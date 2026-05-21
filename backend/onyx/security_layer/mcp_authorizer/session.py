from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MCPSession:
    client_id: str
    session_id: str
    user_id: str
    tenant_id: str
    scopes: set[str]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes
