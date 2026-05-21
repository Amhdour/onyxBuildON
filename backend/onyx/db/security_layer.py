from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Float, Index, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from onyx.db.models import Base


class SecurityAuditEvent(Base):
    __tablename__ = "security_audit_events"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: str(uuid4()))
    event_type: Mapped[str] = mapped_column(Text, index=True)
    severity: Mapped[str] = mapped_column(Text, index=True)
    action: Mapped[str | None] = mapped_column(Text, nullable=True)
    decision: Mapped[str | None] = mapped_column(Text, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    policy_version: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    actor_user_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    tenant_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    resource_type: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    resource_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    tool_name: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    mcp_server: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    mcp_scope: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    retrieval_document_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    artifact_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    redacted_input: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    redacted_output: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SecurityPolicyDecision(Base):
    __tablename__ = "security_policy_decisions"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: str(uuid4()))
    surface: Mapped[str] = mapped_column(Text, index=True)
    action: Mapped[str] = mapped_column(Text, index=True)
    decision: Mapped[str] = mapped_column(Text, index=True)
    reason: Mapped[str] = mapped_column(Text)
    rule_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    policy_version: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    actor_user_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    tenant_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    resource_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    context_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SecurityApprovalRequest(Base):
    __tablename__ = "security_approval_requests"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: str(uuid4()))
    status: Mapped[str] = mapped_column(Text, index=True)
    surface: Mapped[str] = mapped_column(Text, index=True)
    action: Mapped[str] = mapped_column(Text, index=True)
    tool_name: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    resource_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by_user_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    approved_by_user_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    tenant_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_context_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SecurityLaunchGateRun(Base):
    __tablename__ = "security_launch_gate_runs"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: str(uuid4()))
    gate_name: Mapped[str] = mapped_column(Text, index=True)
    status: Mapped[str] = mapped_column(Text, index=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    report_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_user_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    tenant_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SecurityFinding(Base):
    __tablename__ = "security_findings"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: str(uuid4()))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text, index=True)
    status: Mapped[str] = mapped_column(Text, index=True)
    source: Mapped[str] = mapped_column(Text, index=True)
    surface: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_user_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SecurityArtifactScan(Base):
    __tablename__ = "security_artifact_scans"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: str(uuid4()))
    artifact_id: Mapped[str] = mapped_column(Text, index=True)
    artifact_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    decision: Mapped[str] = mapped_column(Text, index=True)
    risk_level: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanner_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    actor_user_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SecurityRetrievalEvent(Base):
    __tablename__ = "security_retrieval_events"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: str(uuid4()))
    query_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    document_id: Mapped[str] = mapped_column(Text, index=True)
    chunk_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    connector_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    decision: Mapped[str] = mapped_column(Text, index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    acl_proof_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    actor_user_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class SecurityMCPEvent(Base):
    __tablename__ = "security_mcp_events"
    id: Mapped[str] = mapped_column(Text, primary_key=True, default=lambda: str(uuid4()))
    mcp_server: Mapped[str] = mapped_column(Text, index=True)
    mcp_tool: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str] = mapped_column(Text)
    decision: Mapped[str] = mapped_column(Text, index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_user_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    context_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
