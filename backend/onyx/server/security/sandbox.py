from fastapi import APIRouter, Depends, Query

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.security_layer.audit.service import AuditService
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter(prefix="/sandbox")


@router.get("/gates")
def get_sandbox_gates(
    _: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS)),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, object]]:
    return AuditService().list_audit_events(
        filters={"tenant_id": get_current_tenant_id(), "surface": "sandbox"},
        limit=limit,
        offset=offset,
    )
