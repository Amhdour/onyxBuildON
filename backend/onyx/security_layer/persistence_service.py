from __future__ import annotations

from datetime import datetime
from datetime import timedelta
import hashlib
import json
from typing import Any

from sqlalchemy import func
from sqlalchemy import select

from onyx.db.engine.sql_engine import get_session_with_current_tenant
from onyx.db.security_layer import SecurityApprovalRequest
from onyx.db.security_layer import SecurityArtifactScan
from onyx.db.security_layer import SecurityLaunchGateRun
from onyx.db.security_layer import SecurityMCPEvent
from onyx.db.security_layer import SecurityPolicyDecision
from onyx.db.security_layer import SecurityRetrievalEvent
from onyx.security_layer.redaction import redact_security_payload


class SecurityPersistenceService:
    @staticmethod
    def approval_argument_hash(tool_args: dict[str, Any]) -> str:
        payload = json.dumps(tool_args, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def create_approval_request(
        self,
        *,
        tenant_id: str | None,
        user_id: str | None,
        session_id: str | None,
        tool_name: str,
        action: str,
        resource: str | None,
        tool_args: dict[str, Any],
        expires_in_seconds: int = 600,
    ) -> SecurityApprovalRequest:
        with get_session_with_current_tenant() as db_session:
            now = datetime.utcnow()
            row = SecurityApprovalRequest(
                status="pending",
                surface="tool_execution",
                action=action,
                tool_name=tool_name,
                resource_type="tool",
                resource_id=resource or tool_name,
                requested_by_user_id=user_id,
                tenant_id=tenant_id,
                session_id=session_id,
                reason="runtime approval required",
                request_context_json={"argument_hash": self.approval_argument_hash(tool_args)},
                expires_at=now + timedelta(seconds=expires_in_seconds),
                created_at=now,
                updated_at=now,
            )
            db_session.add(row)
            db_session.commit()
            db_session.refresh(row)
            return row

    def consume_matching_approved_request(
        self,
        *,
        tenant_id: str | None,
        user_id: str | None,
        session_id: str | None,
        tool_name: str,
        action: str,
        resource: str | None,
        tool_args: dict[str, Any],
    ) -> tuple[str, SecurityApprovalRequest | None]:
        with get_session_with_current_tenant() as db_session:
            stmt = (
                select(SecurityApprovalRequest)
                .where(SecurityApprovalRequest.tenant_id == tenant_id)
                .where(SecurityApprovalRequest.requested_by_user_id == user_id)
                .where(SecurityApprovalRequest.session_id == session_id)
                .where(SecurityApprovalRequest.tool_name == tool_name)
                .where(SecurityApprovalRequest.action == action)
                .where(SecurityApprovalRequest.resource_id == (resource or tool_name))
                .order_by(SecurityApprovalRequest.created_at.desc())
            )
            row = db_session.execute(stmt).scalars().first()
            if row is None:
                return ("missing", None)
            if row.status == "denied":
                return ("denied", row)
            if row.status == "consumed":
                return ("consumed", row)
            if row.expires_at <= datetime.utcnow():
                row.status = "expired"
                row.updated_at = datetime.utcnow()
                db_session.commit()
                db_session.refresh(row)
                return ("expired", row)
            arg_hash = self.approval_argument_hash(tool_args)
            expected_hash = (row.request_context_json or {}).get("argument_hash")
            if arg_hash != expected_hash:
                return ("hash_mismatch", row)
            if row.status != "approved":
                return ("pending", row)
            row.status = "consumed"
            row.updated_at = datetime.utcnow()
            db_session.commit()
            db_session.refresh(row)
            return ("approved_and_consumed", row)

    def _apply_common_filters(self, stmt: Any, model: Any, filters: dict[str, Any]) -> Any:
        if tenant_id := filters.get("tenant_id"):
            stmt = stmt.where(model.tenant_id == str(tenant_id))
        if user_id := filters.get("user_id"):
            actor_field = getattr(model, "actor_user_id", None) or getattr(model, "requested_by_user_id", None)
            if actor_field is not None:
                stmt = stmt.where(actor_field == str(user_id))
        for key in ("decision", "severity", "status", "surface", "correlation_id"):
            if value := filters.get(key):
                if hasattr(model, key):
                    stmt = stmt.where(getattr(model, key) == str(value))
        if created_at_from := filters.get("created_at_from"):
            stmt = stmt.where(model.created_at >= created_at_from)
        if created_at_to := filters.get("created_at_to"):
            stmt = stmt.where(model.created_at <= created_at_to)
        return stmt

    def list_policy_decisions(self, filters: dict[str, Any], limit: int, offset: int) -> list[SecurityPolicyDecision]:
        with get_session_with_current_tenant() as db_session:
            stmt = select(SecurityPolicyDecision).order_by(SecurityPolicyDecision.created_at.desc())
            stmt = self._apply_common_filters(stmt, SecurityPolicyDecision, filters).limit(limit).offset(offset)
            return list(db_session.execute(stmt).scalars().all())

    def list_retrieval_events(self, filters: dict[str, Any], limit: int, offset: int) -> list[SecurityRetrievalEvent]:
        with get_session_with_current_tenant() as db_session:
            stmt = select(SecurityRetrievalEvent).order_by(SecurityRetrievalEvent.created_at.desc())
            stmt = self._apply_common_filters(stmt, SecurityRetrievalEvent, filters).limit(limit).offset(offset)
            return list(db_session.execute(stmt).scalars().all())

    def list_mcp_events(self, filters: dict[str, Any], limit: int, offset: int) -> list[SecurityMCPEvent]:
        with get_session_with_current_tenant() as db_session:
            stmt = select(SecurityMCPEvent).order_by(SecurityMCPEvent.created_at.desc())
            stmt = self._apply_common_filters(stmt, SecurityMCPEvent, filters).limit(limit).offset(offset)
            return list(db_session.execute(stmt).scalars().all())

    def list_artifact_scans(self, filters: dict[str, Any], limit: int, offset: int) -> list[SecurityArtifactScan]:
        with get_session_with_current_tenant() as db_session:
            stmt = select(SecurityArtifactScan).order_by(SecurityArtifactScan.created_at.desc())
            stmt = self._apply_common_filters(stmt, SecurityArtifactScan, filters).limit(limit).offset(offset)
            rows = list(db_session.execute(stmt).scalars().all())
            for row in rows:
                row.findings_json = redact_security_payload(row.findings_json)
            return rows

    def list_launch_gate_runs(self, filters: dict[str, Any], limit: int, offset: int) -> list[SecurityLaunchGateRun]:
        with get_session_with_current_tenant() as db_session:
            stmt = select(SecurityLaunchGateRun).order_by(SecurityLaunchGateRun.created_at.desc())
            stmt = self._apply_common_filters(stmt, SecurityLaunchGateRun, filters).limit(limit).offset(offset)
            return list(db_session.execute(stmt).scalars().all())

    def list_approvals(self, filters: dict[str, Any], limit: int, offset: int) -> list[SecurityApprovalRequest]:
        with get_session_with_current_tenant() as db_session:
            stmt = select(SecurityApprovalRequest).order_by(SecurityApprovalRequest.created_at.desc())
            stmt = self._apply_common_filters(stmt, SecurityApprovalRequest, filters).limit(limit).offset(offset)
            return list(db_session.execute(stmt).scalars().all())

    def set_approval_status(self, approval_id: str, status: str, approved_by_user_id: str | None = None) -> SecurityApprovalRequest | None:
        with get_session_with_current_tenant() as db_session:
            row = db_session.get(SecurityApprovalRequest, approval_id)
            if row is None:
                return None
            row.status = status
            if approved_by_user_id:
                row.approved_by_user_id = approved_by_user_id
            row.updated_at = datetime.utcnow()
            db_session.commit()
            db_session.refresh(row)
            return row
