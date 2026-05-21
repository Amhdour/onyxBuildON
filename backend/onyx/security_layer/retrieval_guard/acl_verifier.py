from __future__ import annotations

from onyx.context.search.models import InferenceChunk
from onyx.security_layer.retrieval_guard.models import ACLState
from onyx.security_layer.retrieval_guard.models import ChunkACLVerdict
from onyx.security_layer.retrieval_guard.models import RetrievalDecision

_ALLOWED_STATES = {ACLState.PUBLIC, ACLState.PRIVATE_ALLOW}


def verify_chunk_metadata_acl(acl_state: ACLState) -> ChunkACLVerdict:
    if acl_state in _ALLOWED_STATES:
        return ChunkACLVerdict(
            decision=RetrievalDecision.ALLOW,
            reason=f"acl_state={acl_state.value}",
            acl_state=acl_state,
        )

    return ChunkACLVerdict(
        decision=RetrievalDecision.DENY,
        reason=f"acl_state={acl_state.value}",
        acl_state=acl_state,
    )


def verify_source_of_truth_acl(chunk: InferenceChunk, user_id: str | None, tenant_id: str | None) -> ChunkACLVerdict | None:
    acl = chunk.metadata.get("onyx_acl")
    if not isinstance(acl, dict):
        return None
    if tenant_id and acl.get("tenant_id") and str(acl.get("tenant_id")) != str(tenant_id):
        return ChunkACLVerdict(decision=RetrievalDecision.DENY, reason="source_of_truth tenant mismatch", acl_state=ACLState.CROSS_TENANT)
    if acl.get("deleted") is True:
        return ChunkACLVerdict(decision=RetrievalDecision.DENY, reason="source_of_truth deleted document", acl_state=ACLState.DELETED_PENDING_PRUNE)
    allowed_users = set(str(v) for v in acl.get("user_ids", []))
    allowed_groups = set(str(v) for v in acl.get("group_ids", []))
    user_groups = set(str(v) for v in chunk.metadata.get("onyx_user_group_ids", []))
    if user_id and (user_id in allowed_users or (allowed_groups and (allowed_groups & user_groups))):
        return ChunkACLVerdict(decision=RetrievalDecision.ALLOW, reason="source_of_truth grant", acl_state=ACLState.PRIVATE_ALLOW)
    return ChunkACLVerdict(decision=RetrievalDecision.DENY, reason="source_of_truth denied", acl_state=ACLState.PRIVATE_DENY)


def authorize_retrieved_chunk(chunk: InferenceChunk, acl_state: ACLState, user_id: str | None, tenant_id: str | None) -> ChunkACLVerdict:
    source_verdict = verify_source_of_truth_acl(chunk, user_id=user_id, tenant_id=tenant_id)
    if source_verdict is not None:
        return source_verdict
    return verify_chunk_metadata_acl(acl_state)
