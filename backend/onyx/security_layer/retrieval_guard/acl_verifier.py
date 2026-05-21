from __future__ import annotations

from onyx.security_layer.retrieval_guard.models import ACLState
from onyx.security_layer.retrieval_guard.models import ChunkACLVerdict
from onyx.security_layer.retrieval_guard.models import RetrievalDecision

_ALLOWED_STATES = {ACLState.PUBLIC, ACLState.PRIVATE_ALLOW}


def verify_acl_state(acl_state: ACLState) -> ChunkACLVerdict:
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
