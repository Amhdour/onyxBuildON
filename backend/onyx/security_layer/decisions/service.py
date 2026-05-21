from __future__ import annotations

from typing import Any

from sqlalchemy import select

from onyx.db.engine.sql_engine import get_session_with_current_tenant
from onyx.db.security_layer import SecurityPolicyDecision
from onyx.security_layer.decisions.models import SecurityDecision


class DecisionService:
    def create_policy_decision(self, decision: SecurityDecision) -> SecurityDecision:
        with get_session_with_current_tenant() as db_session:
            db_session.add(
                SecurityPolicyDecision(
                    id=decision.decision_id,
                    surface=decision.evidence.get("surface", "unknown"),
                    action=decision.action,
                    decision=decision.decision.value,
                    reason=decision.reason,
                    rule_id=decision.matched_rules[0] if decision.matched_rules else "default",
                    policy_version=decision.evidence.get("policy_version"),
                    actor_user_id=decision.subject_id,
                    tenant_id=decision.tenant_id,
                    session_id=decision.session_id,
                    correlation_id=decision.evidence.get("correlation_id"),
                    resource_type=decision.resource_type,
                    resource_id=decision.resource_id,
                    tool_name=decision.evidence.get("tool_name"),
                    risk_level=decision.risk_level.value,
                    context_json=decision.evidence,
                    created_at=decision.created_at,
                )
            )
            db_session.commit()
        return decision

    def create(self, decision: SecurityDecision) -> SecurityDecision:
        return self.create_policy_decision(decision)

    def list_policy_decisions(self, filters: dict[str, Any] | None = None, limit: int = 100, offset: int = 0) -> list[SecurityPolicyDecision]:
        filters = filters or {}
        with get_session_with_current_tenant() as db_session:
            stmt = select(SecurityPolicyDecision).order_by(SecurityPolicyDecision.created_at.desc()).limit(limit).offset(offset)
            if tenant_id := filters.get("tenant_id"):
                stmt = stmt.where(SecurityPolicyDecision.tenant_id == str(tenant_id))
            return list(db_session.execute(stmt).scalars().all())

    def list_all(self) -> list[SecurityDecision]:
        return []
