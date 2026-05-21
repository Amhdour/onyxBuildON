from fastapi import APIRouter, Depends

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.security_layer.findings.service import FindingService
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter()


@router.get("/findings")
def get_findings(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> list[dict[str, object]]:
    tenant_id = get_current_tenant_id()
    rows = FindingService().list_findings(filters={"tenant_id": tenant_id}, limit=100, offset=0)
    return [
        {
            "id": row.id,
            "title": row.title,
            "description": row.description,
            "severity": row.severity,
            "status": row.status,
            "tenant_id": row.tenant_id,
            "correlation_id": row.correlation_id,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]
