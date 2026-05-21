from fastapi import APIRouter, Depends, Query

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.security_layer.persistence_service import SecurityPersistenceService
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter(prefix="/approvals")


@router.get("")
def list_approvals(
    _: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS)),
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, object]]:
    rows = SecurityPersistenceService().list_approvals(
        filters={"tenant_id": get_current_tenant_id(), "status": status},
        limit=limit,
        offset=offset,
    )
    return [row.__dict__ for row in rows]


@router.post("/{approval_id}/approve")
def approve_request(
    approval_id: str,
    user: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS)),
) -> dict[str, object]:
    row = SecurityPersistenceService().set_approval_status(approval_id, "approved", approved_by_user_id=str(user.id))
    return {"ok": row is not None, "approval_id": approval_id, "status": "approved" if row else "not_found"}


@router.post("/{approval_id}/deny")
def deny_request(
    approval_id: str,
    _: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS)),
) -> dict[str, object]:
    row = SecurityPersistenceService().set_approval_status(approval_id, "denied")
    return {"ok": row is not None, "approval_id": approval_id, "status": "denied" if row else "not_found"}
