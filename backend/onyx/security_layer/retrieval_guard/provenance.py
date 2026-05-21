from __future__ import annotations

from onyx.context.search.models import InferenceChunk
from onyx.security_layer.retrieval_guard.models import ACLState
from onyx.security_layer.retrieval_guard.models import RetrievalDecision
from onyx.security_layer.retrieval_guard.models import RetrievalProvenance


def build_provenance(
    *,
    chunk: InferenceChunk,
    tenant_id: str,
    acl_state: ACLState,
    permission_source: str,
    user_id: str,
    session_id: str,
    decision: RetrievalDecision,
    reason: str,
) -> RetrievalProvenance:
    connector_id = chunk.metadata.get("connector_id")
    connector_id_str = str(connector_id) if connector_id is not None else None

    return RetrievalProvenance(
        document_id=chunk.document_id,
        chunk_id=chunk.chunk_id,
        tenant_id=tenant_id,
        connector_id=connector_id_str,
        source_type=str(chunk.source_type),
        acl_state=acl_state,
        permission_source=permission_source,
        user_id=user_id,
        session_id=session_id,
        decision=decision,
        reason=reason,
    )
