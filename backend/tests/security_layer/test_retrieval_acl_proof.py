from __future__ import annotations

from datetime import datetime

from onyx.configs.constants import DocumentSource
from onyx.context.search.models import InferenceChunk
from onyx.security_layer.audit.service import AuditService
from onyx.security_layer.findings.service import FindingService
from onyx.security_layer.retrieval_guard.guard import apply_retrieval_acl_guard


def _chunk(acl_state: str, *, tenant_id: str = "t1") -> InferenceChunk:
    return InferenceChunk(
        document_id="doc-1",
        chunk_id=1,
        blurb="blurb",
        content="content",
        source_type=DocumentSource.WEB,
        semantic_identifier="sid",
        title="title",
        boost=0,
        score=0.9,
        hidden=False,
        metadata={"acl_state": acl_state, "tenant_id": tenant_id, "permission_source": "index_metadata"},
        match_highlights=[],
        doc_summary="",
        chunk_context="",
        updated_at=datetime.utcnow(),
    )


def test_public_chunk_allowed() -> None:
    result = apply_retrieval_acl_guard([_chunk("public")], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.allowed_chunks) == 1


def test_private_allowed_chunk_allowed() -> None:
    result = apply_retrieval_acl_guard([_chunk("private_allow")], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.allowed_chunks) == 1


def test_private_denied_chunk_denied() -> None:
    result = apply_retrieval_acl_guard([_chunk("private_deny")], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.denied_chunks) == 1


def test_unknown_acl_denied() -> None:
    result = apply_retrieval_acl_guard([_chunk("not_real")], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.denied_chunks) == 1


def test_stale_acl_denied() -> None:
    result = apply_retrieval_acl_guard([_chunk("stale_acl")], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.denied_chunks) == 1


def test_sync_failed_denied() -> None:
    result = apply_retrieval_acl_guard([_chunk("sync_failed")], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.denied_chunks) == 1


def test_cross_tenant_denied() -> None:
    result = apply_retrieval_acl_guard([_chunk("public", tenant_id="t2")], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.denied_chunks) == 1


def test_deleted_pending_prune_denied() -> None:
    result = apply_retrieval_acl_guard([_chunk("deleted_pending_prune")], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.denied_chunks) == 1


def test_external_permission_unverified_denied() -> None:
    result = apply_retrieval_acl_guard([_chunk("external_permission_unverified")], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.denied_chunks) == 1


def test_audit_event_created() -> None:
    audit = AuditService()
    apply_retrieval_acl_guard([_chunk("public")], tenant_id="t1", user_id="u1", session_id="s1", audit_service=audit)
    assert len(audit.list_all()) == 1


def test_provenance_logged() -> None:
    result = apply_retrieval_acl_guard([_chunk("public")], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.provenance) == 1
    assert result.provenance[0].acl_state.value == "public"


def test_finding_created_for_denied_high_risk_retrieval() -> None:
    finding_service = FindingService()
    result = apply_retrieval_acl_guard(
        [_chunk("cross_tenant")],
        tenant_id="t1",
        user_id="u1",
        session_id="s1",
        finding_service=finding_service,
    )
    assert len(result.findings) == 1


def test_security_retrieval_guard_disabled_preserves_existing_behavior(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_RETRIEVAL_GUARD_ENABLED", "false")
    result = apply_retrieval_acl_guard([_chunk("private_deny")], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.allowed_chunks) == 1
    assert len(result.denied_chunks) == 0


def test_source_of_truth_deleted_document_denied() -> None:
    c = _chunk("public")
    c.metadata["onyx_acl"] = {"tenant_id": "t1", "deleted": True}
    result = apply_retrieval_acl_guard([c], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.denied_chunks) == 1


def test_source_of_truth_group_access_insufficient_denied() -> None:
    c = _chunk("public")
    c.metadata["onyx_acl"] = {"tenant_id": "t1", "group_ids": ["g-admin"]}
    c.metadata["onyx_user_group_ids"] = ["g-user"]
    result = apply_retrieval_acl_guard([c], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.denied_chunks) == 1


def test_retrieval_metadata_fallback_still_works() -> None:
    c = _chunk("public")
    c.metadata.pop("onyx_acl", None)
    result = apply_retrieval_acl_guard([c], tenant_id="t1", user_id="u1", session_id="s1")
    assert len(result.allowed_chunks) == 1
