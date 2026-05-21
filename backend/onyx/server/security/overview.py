from fastapi import APIRouter, Depends

from onyx.auth.permissions import require_permission
from onyx.configs.app_configs import SECURITY_LAYER_ENABLED
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.security_layer.findings.service import FindingService
from onyx.security_layer.models import PolicyMode
from onyx.security_layer.persistence_service import SecurityPersistenceService
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter()


@router.get("/overview")
def get_security_overview(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> dict[str, object]:
    tenant_id = get_current_tenant_id()
    persistence = SecurityPersistenceService()
    findings = FindingService().list_findings(filters={"tenant_id": tenant_id}, limit=100, offset=0)
    denied_tools = persistence.list_policy_decisions({"tenant_id": tenant_id, "decision": "deny", "surface": "tool_execution"}, 10, 0)
    denied_retrieval = persistence.list_retrieval_events({"tenant_id": tenant_id, "decision": "deny"}, 10, 0)
    denied_mcp = persistence.list_mcp_events({"tenant_id": tenant_id, "decision": "deny"}, 10, 0)
    return {
        "security_layer_enabled": SECURITY_LAYER_ENABLED,
        "policy_mode": PolicyMode.ENFORCE.value if SECURITY_LAYER_ENABLED else PolicyMode.OBSERVE.value,
        "open_findings_count": sum(1 for finding in findings if finding.status == "open"),
        "critical_findings_count": sum(1 for finding in findings if finding.severity == "critical"),
        "high_findings_count": sum(1 for finding in findings if finding.severity == "high"),
        "recent_denied_tool_calls": [row.__dict__ for row in denied_tools],
        "recent_denied_retrieval_events": [row.__dict__ for row in denied_retrieval],
        "recent_denied_mcp_events": [row.__dict__ for row in denied_mcp],
    }
