"""security layer persistence tables

Revision ID: 9b1d2f7c4a10
Revises: ffc707a226b4
Create Date: 2026-05-21
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '9b1d2f7c4a10'
down_revision = 'ffc707a226b4'
branch_labels = None
depends_on = None


def _create(name: str, cols: list[sa.Column], indexes: list[tuple[str, list[str]]]) -> None:
    op.create_table(name, *cols)
    for idx, idx_cols in indexes:
        op.create_index(idx, name, idx_cols)


def upgrade() -> None:
    js = postgresql.JSONB(astext_type=sa.Text())
    ts = sa.DateTime(timezone=True)
    txt = sa.Text()
    _create('security_audit_events', [sa.Column('id', txt, primary_key=True), sa.Column('event_type', txt), sa.Column('severity', txt), sa.Column('action', txt), sa.Column('decision', txt), sa.Column('reason', txt), sa.Column('rule_id', txt), sa.Column('policy_version', txt), sa.Column('actor_user_id', txt), sa.Column('tenant_id', txt), sa.Column('session_id', txt), sa.Column('correlation_id', txt), sa.Column('resource_type', txt), sa.Column('resource_id', txt), sa.Column('tool_name', txt), sa.Column('mcp_server', txt), sa.Column('mcp_scope', txt), sa.Column('retrieval_document_id', txt), sa.Column('artifact_id', txt), sa.Column('metadata_json', js), sa.Column('redacted_input', js), sa.Column('redacted_output', js), sa.Column('created_at', ts, nullable=False)], [('ix_security_audit_events_event_type',['event_type']),('ix_security_audit_events_severity',['severity']),('ix_security_audit_events_tenant_id',['tenant_id']),('ix_security_audit_events_actor_user_id',['actor_user_id']),('ix_security_audit_events_created_at',['created_at'])])
    _create('security_policy_decisions', [sa.Column('id', txt, primary_key=True), sa.Column('surface', txt), sa.Column('action', txt), sa.Column('decision', txt), sa.Column('reason', txt, nullable=False), sa.Column('rule_id', txt), sa.Column('policy_version', txt), sa.Column('actor_user_id', txt), sa.Column('tenant_id', txt), sa.Column('session_id', txt), sa.Column('correlation_id', txt), sa.Column('resource_type', txt), sa.Column('resource_id', txt), sa.Column('tool_name', txt), sa.Column('risk_level', txt), sa.Column('context_json', js), sa.Column('created_at', ts, nullable=False)], [('ix_security_policy_decisions_surface',['surface']),('ix_security_policy_decisions_action',['action']),('ix_security_policy_decisions_decision',['decision']),('ix_security_policy_decisions_tenant_id',['tenant_id']),('ix_security_policy_decisions_created_at',['created_at'])])
    _create('security_findings', [sa.Column('id', txt, primary_key=True), sa.Column('title', txt, nullable=False), sa.Column('description', txt, nullable=False), sa.Column('severity', txt, nullable=False), sa.Column('status', txt, nullable=False), sa.Column('source', txt, nullable=False), sa.Column('surface', txt), sa.Column('rule_id', txt), sa.Column('policy_version', txt), sa.Column('actor_user_id', txt), sa.Column('tenant_id', txt), sa.Column('session_id', txt), sa.Column('correlation_id', txt), sa.Column('evidence_json', js), sa.Column('remediation', txt), sa.Column('created_at', ts, nullable=False), sa.Column('updated_at', ts, nullable=False)], [('ix_security_findings_severity',['severity']),('ix_security_findings_status',['status']),('ix_security_findings_source',['source']),('ix_security_findings_tenant_id',['tenant_id']),('ix_security_findings_created_at',['created_at'])])
    _create('security_artifact_scans', [sa.Column('id', txt, primary_key=True), sa.Column('artifact_id', txt, nullable=False), sa.Column('artifact_type', txt), sa.Column('decision', txt, nullable=False), sa.Column('risk_level', txt), sa.Column('scanner_version', txt), sa.Column('findings_json', js), sa.Column('actor_user_id', txt), sa.Column('tenant_id', txt), sa.Column('session_id', txt), sa.Column('correlation_id', txt), sa.Column('created_at', ts, nullable=False)], [('ix_security_artifact_scans_artifact_id',['artifact_id']),('ix_security_artifact_scans_decision',['decision']),('ix_security_artifact_scans_tenant_id',['tenant_id']),('ix_security_artifact_scans_created_at',['created_at'])])
    _create('security_retrieval_events', [sa.Column('id', txt, primary_key=True), sa.Column('query_id', txt), sa.Column('document_id', txt, nullable=False), sa.Column('chunk_id', txt), sa.Column('connector_id', txt), sa.Column('decision', txt, nullable=False), sa.Column('reason', txt), sa.Column('acl_proof_json', js), sa.Column('actor_user_id', txt), sa.Column('tenant_id', txt), sa.Column('session_id', txt), sa.Column('correlation_id', txt), sa.Column('created_at', ts, nullable=False)], [('ix_security_retrieval_events_document_id',['document_id']),('ix_security_retrieval_events_decision',['decision']),('ix_security_retrieval_events_tenant_id',['tenant_id']),('ix_security_retrieval_events_created_at',['created_at'])])
    _create('security_mcp_events', [sa.Column('id', txt, primary_key=True), sa.Column('mcp_server', txt, nullable=False), sa.Column('mcp_tool', txt), sa.Column('scope', txt), sa.Column('action', txt, nullable=False), sa.Column('decision', txt, nullable=False), sa.Column('reason', txt), sa.Column('actor_user_id', txt), sa.Column('tenant_id', txt), sa.Column('session_id', txt), sa.Column('correlation_id', txt), sa.Column('context_json', js), sa.Column('created_at', ts, nullable=False)], [('ix_security_mcp_events_mcp_server',['mcp_server']),('ix_security_mcp_events_decision',['decision']),('ix_security_mcp_events_tenant_id',['tenant_id']),('ix_security_mcp_events_created_at',['created_at'])])
    _create('security_launch_gate_runs', [sa.Column('id', txt, primary_key=True), sa.Column('gate_name', txt, nullable=False), sa.Column('status', txt, nullable=False), sa.Column('score', sa.Float()), sa.Column('summary', txt), sa.Column('evidence_json', js), sa.Column('report_path', txt), sa.Column('actor_user_id', txt), sa.Column('tenant_id', txt), sa.Column('correlation_id', txt), sa.Column('created_at', ts, nullable=False)], [('ix_security_launch_gate_runs_gate_name',['gate_name']),('ix_security_launch_gate_runs_status',['status']),('ix_security_launch_gate_runs_tenant_id',['tenant_id']),('ix_security_launch_gate_runs_created_at',['created_at'])])
    _create('security_approval_requests', [sa.Column('id', txt, primary_key=True), sa.Column('status', txt, nullable=False), sa.Column('surface', txt, nullable=False), sa.Column('action', txt, nullable=False), sa.Column('tool_name', txt), sa.Column('resource_type', txt), sa.Column('resource_id', txt), sa.Column('requested_by_user_id', txt), sa.Column('approved_by_user_id', txt), sa.Column('tenant_id', txt), sa.Column('session_id', txt), sa.Column('correlation_id', txt), sa.Column('reason', txt), sa.Column('request_context_json', js), sa.Column('expires_at', ts, nullable=False), sa.Column('created_at', ts, nullable=False), sa.Column('updated_at', ts, nullable=False)], [('ix_security_approval_requests_status',['status']),('ix_security_approval_requests_surface',['surface']),('ix_security_approval_requests_action',['action']),('ix_security_approval_requests_tenant_id',['tenant_id']),('ix_security_approval_requests_expires_at',['expires_at']),('ix_security_approval_requests_created_at',['created_at'])])


def downgrade() -> None:
    for table in ['security_approval_requests','security_launch_gate_runs','security_mcp_events','security_retrieval_events','security_artifact_scans','security_findings','security_policy_decisions','security_audit_events']:
        op.drop_table(table)
