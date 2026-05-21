from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class ACLState(str, Enum):
    PUBLIC = "public"
    PRIVATE_ALLOW = "private_allow"
    PRIVATE_DENY = "private_deny"
    UNKNOWN_ACL = "unknown_acl"
    STALE_ACL = "stale_acl"
    SYNC_FAILED = "sync_failed"
    DELETED_PENDING_PRUNE = "deleted_pending_prune"
    EXTERNAL_PERMISSION_UNVERIFIED = "external_permission_unverified"
    CROSS_TENANT = "cross_tenant"


class RetrievalDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class RetrievalProvenance(BaseModel):
    document_id: str
    chunk_id: int
    tenant_id: str
    connector_id: str | None
    source_type: str
    acl_state: ACLState
    permission_source: str
    user_id: str
    session_id: str
    decision: RetrievalDecision
    reason: str


class ChunkACLVerdict(BaseModel):
    decision: RetrievalDecision
    reason: str
    acl_state: ACLState
