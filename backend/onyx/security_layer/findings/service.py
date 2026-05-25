from __future__ import annotations

from typing import Any

from sqlalchemy import func
from sqlalchemy import select

from onyx.db.engine.sql_engine import get_session_with_current_tenant
from onyx.db.security_layer import SecurityFinding as DbSecurityFinding
from onyx.security_layer.decisions.models import DecisionType
from onyx.security_layer.decisions.models import SecurityDecision
from onyx.security_layer.findings.models import FindingSeverity
from onyx.security_layer.findings.models import FindingStatus
from onyx.security_layer.findings.models import SecurityFinding
from onyx.security_layer.persistence.db_availability import is_security_layer_db_available


class FindingService:
    _memory_findings: list[SecurityFinding] = []

    def create(self, finding: SecurityFinding) -> SecurityFinding:
        if not is_security_layer_db_available():
            self._memory_findings.append(finding)
            return finding
        with get_session_with_current_tenant() as db_session:
            db_session.add(
                DbSecurityFinding(
                    id=finding.finding_id,
                    title=finding.title,
                    description=finding.category,
                    severity=finding.severity.value,
                    status=finding.status.value,
                    source="security_layer",
                    surface=finding.asset_type,
                    rule_id=finding.policy_id,
                    actor_user_id=None,
                    tenant_id=finding.tenant_id,
                    session_id=None,
                    correlation_id=finding.evidence.get("correlation_id") if isinstance(finding.evidence, dict) else None,
                    evidence_json=finding.evidence,
                    remediation=finding.recommended_fix,
                    created_at=finding.created_at,
                    updated_at=finding.updated_at,
                )
            )
            db_session.commit()
        return finding

    def create_from_decision(self, decision: SecurityDecision) -> SecurityFinding | None:
        if decision.decision == DecisionType.ALLOW and decision.risk_level.value in {"low", "medium"}:
            return None
        finding = SecurityFinding(
            title=f"Risky action: {decision.action}",
            category="policy_violation",
            severity=FindingSeverity(decision.risk_level.value),
            tenant_id=decision.tenant_id,
            asset_type=decision.resource_type,
            asset_id=decision.resource_id,
            policy_id=decision.policy_id,
            evidence=decision.evidence,
            recommended_fix="Review policy and reduce risk before launch",
            blocking_launch=decision.risk_level.value in {"high", "critical"},
        )
        return self.create(finding)

    def update_finding_status(self, finding_id: str, status: FindingStatus) -> bool:
        if not is_security_layer_db_available():
            for finding in self._memory_findings:
                if finding.finding_id == finding_id:
                    finding.status = status
                    return True
            return False
        with get_session_with_current_tenant() as db_session:
            row = db_session.get(DbSecurityFinding, finding_id)
            if row is None:
                return False
            row.status = status.value
            db_session.commit()
            return True

    def list_findings(self, filters: dict[str, Any] | None = None, limit: int = 100, offset: int = 0) -> list[DbSecurityFinding]:
        filters = filters or {}
        if not is_security_layer_db_available():
            return []
        with get_session_with_current_tenant() as db_session:
            stmt = select(DbSecurityFinding).order_by(DbSecurityFinding.created_at.desc()).limit(limit).offset(offset)
            if tenant_id := filters.get("tenant_id"):
                stmt = stmt.where(DbSecurityFinding.tenant_id == str(tenant_id))
            if status := filters.get("status"):
                stmt = stmt.where(DbSecurityFinding.status == str(status))
            if severity := filters.get("severity"):
                stmt = stmt.where(DbSecurityFinding.severity == str(severity))
            return list(db_session.execute(stmt).scalars().all())

    def count_findings(self, filters: dict[str, Any] | None = None) -> int:
        filters = filters or {}
        if not is_security_layer_db_available():
            return len(self._memory_findings)
        with get_session_with_current_tenant() as db_session:
            stmt = select(func.count()).select_from(DbSecurityFinding)
            if tenant_id := filters.get("tenant_id"):
                stmt = stmt.where(DbSecurityFinding.tenant_id == str(tenant_id))
            return int(db_session.execute(stmt).scalar_one())

    def list_all(self) -> list[SecurityFinding]:
        if not is_security_layer_db_available():
            return list(self._memory_findings)
        rows = self.list_findings()
        return [
            SecurityFinding(
                finding_id=row.id,
                title=row.title,
                category=row.description,
                severity=FindingSeverity(row.severity),
                status=FindingStatus(row.status),
                tenant_id=row.tenant_id or "",
                asset_type=row.surface or "",
                asset_id="",
                policy_id=row.rule_id or "",
                evidence=(row.evidence_json or {}),
                recommended_fix=row.remediation or "",
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
            for row in rows
        ]
