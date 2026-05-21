from __future__ import annotations

import os
from dataclasses import dataclass

from onyx.context.search.models import InferenceChunk
from onyx.security_layer.audit.models import AuditEvent
from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.decisions.models import DecisionType, RiskLevel, SecurityDecision
from onyx.security_layer.decisions.service import DecisionService
from onyx.security_layer.mode import is_observe_mode
from onyx.security_layer.findings.models import FindingSeverity
from onyx.security_layer.findings.models import SecurityFinding
from onyx.security_layer.findings.service import FindingService
from onyx.security_layer.retrieval_guard.acl_verifier import authorize_retrieved_chunk
from onyx.security_layer.retrieval_guard.models import ACLState
from onyx.security_layer.retrieval_guard.models import RetrievalDecision
from onyx.security_layer.retrieval_guard.models import RetrievalProvenance
from onyx.security_layer.retrieval_guard.provenance import build_provenance

_DENIED_FINDING_STATES = {
    ACLState.UNKNOWN_ACL,
    ACLState.STALE_ACL,
    ACLState.SYNC_FAILED,
    ACLState.CROSS_TENANT,
    ACLState.DELETED_PENDING_PRUNE,
}


@dataclass
class RetrievalGuardResult:
    allowed_chunks: list[InferenceChunk]
    denied_chunks: list[InferenceChunk]
    audit_events: list[AuditEvent]
    provenance: list[RetrievalProvenance]
    findings: list[SecurityFinding]


def _acl_state_for_chunk(chunk: InferenceChunk, tenant_id: str) -> ACLState:
    chunk_tenant_id = str(chunk.metadata.get("tenant_id", tenant_id))
    if chunk_tenant_id != tenant_id:
        return ACLState.CROSS_TENANT

    raw_state = chunk.metadata.get("acl_state", ACLState.PUBLIC.value)
    if isinstance(raw_state, list) and raw_state:
        raw_state = raw_state[0]

    try:
        return ACLState(str(raw_state))
    except ValueError:
        return ACLState.UNKNOWN_ACL


def apply_retrieval_acl_guard(
    chunks: list[InferenceChunk],
    *,
    tenant_id: str,
    user_id: str | None,
    session_id: str | None,
    audit_service: AuditService | None = None,
    finding_service: FindingService | None = None,
) -> RetrievalGuardResult:
    if os.getenv("SECURITY_RETRIEVAL_GUARD_ENABLED", "true").lower() == "false":
        return RetrievalGuardResult(
            allowed_chunks=chunks,
            denied_chunks=[],
            audit_events=[],
            provenance=[],
            findings=[],
        )

    audit = audit_service or AuditService()
    finding_svc = finding_service or FindingService()
    decision_service = DecisionService()
    safe_user_id = user_id
    safe_session_id = session_id

    allowed: list[InferenceChunk] = []
    denied: list[InferenceChunk] = []
    events: list[AuditEvent] = []
    provenances: list[RetrievalProvenance] = []
    findings: list[SecurityFinding] = []

    for chunk in chunks:
        acl_state = _acl_state_for_chunk(chunk, tenant_id)
        verdict = authorize_retrieved_chunk(chunk, acl_state, user_id=safe_user_id, tenant_id=tenant_id)
        permission_source = str(chunk.metadata.get("permission_source", "index_metadata"))

        prov = build_provenance(
            chunk=chunk,
            tenant_id=tenant_id,
            acl_state=acl_state,
            permission_source=permission_source,
            user_id=safe_user_id,
            session_id=safe_session_id,
            decision=verdict.decision,
            reason=verdict.reason,
        )
        provenances.append(prov)

        is_allowed = verdict.decision == RetrievalDecision.ALLOW
        if is_allowed or is_observe_mode():
            allowed.append(chunk)
            event_type = "retrieval_result_allowed" if is_allowed else "retrieval_result_observed_risky"
        else:
            denied.append(chunk)
            event_type = "retrieval_result_denied"

        details: dict[str, str | int | float | bool | None] = {
            "document_id": chunk.document_id,
            "chunk_id": chunk.chunk_id,
            "acl_state": acl_state.value,
            "reason": verdict.reason,
        }

        if acl_state == ACLState.UNKNOWN_ACL:
            details["finding"] = "unknown ACL returned"
        elif acl_state == ACLState.STALE_ACL:
            details["finding"] = "stale ACL returned"
        elif acl_state == ACLState.SYNC_FAILED:
            details["finding"] = "sync-failed ACL returned"
        elif acl_state == ACLState.CROSS_TENANT:
            details["finding"] = "cross-tenant retrieval attempted"
        elif acl_state == ACLState.DELETED_PENDING_PRUNE:
            details["finding"] = "deleted document returned"

        decision = SecurityDecision(
            decision=DecisionType.ALLOW if (is_allowed or is_observe_mode()) else DecisionType.DENY,
            risk_level=RiskLevel.LOW if is_allowed else RiskLevel.HIGH,
            reason=verdict.reason,
            policy_id=f"retrieval_acl_{acl_state.value}",
            matched_rules=[acl_state.value],
            evidence={**details, "surface": "retrieval", "correlation_id": f"retrieval-{chunk.document_id}-{chunk.chunk_id}"},
            subject_type="user",
            subject_id=safe_user_id or "missing:user",
            tenant_id=tenant_id,
            session_id=safe_session_id or "missing:session",
            resource_type="chunk",
            resource_id=f"{chunk.document_id}:{chunk.chunk_id}",
            action="retrieve",
        )
        decision_service.create_policy_decision(decision)

        event = audit.record(
            AuditEvent(
                event_type=event_type,
                tenant_id=tenant_id,
                user_id=safe_user_id or "missing",
                session_id=safe_session_id or "missing",
                decision_id=decision.decision_id,
                resource_type="chunk",
                resource_id=f"{chunk.document_id}:{chunk.chunk_id}",
                action="retrieve",
                risk_level="low" if is_allowed else "high",
                details=details,
            )
        )
        events.append(event)

        if not is_allowed and acl_state in _DENIED_FINDING_STATES:
            finding = finding_svc.create(
                SecurityFinding(
                    title="Denied high-risk retrieval result",
                    category="retrieval_acl",
                    severity=FindingSeverity.HIGH,
                    tenant_id=tenant_id,
                    asset_type="chunk",
                    asset_id=f"{chunk.document_id}:{chunk.chunk_id}",
                    policy_id=f"retrieval_acl_{acl_state.value}",
                    evidence=details,
                    recommended_fix="Verify ACL sync and tenant boundaries before allowing retrieval",
                    blocking_launch=False,
                )
            )
            findings.append(finding)

    return RetrievalGuardResult(
        allowed_chunks=allowed,
        denied_chunks=denied,
        audit_events=events,
        provenance=provenances,
        findings=findings,
    )
