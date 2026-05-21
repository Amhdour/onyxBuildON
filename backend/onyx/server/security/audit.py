from fastapi import APIRouter, Depends

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.security_layer.audit.service import AuditService
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter()


@router.get("/audit-events")
def get_audit_events(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> list[dict[str, object]]:
    tenant_id = get_current_tenant_id()
    return AuditService().list_audit_events(filters={"tenant_id": tenant_id}, limit=200, offset=0)
