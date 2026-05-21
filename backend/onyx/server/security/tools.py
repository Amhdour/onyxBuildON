from fastapi import APIRouter, Depends, Query

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.security_layer.persistence_service import SecurityPersistenceService
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter(prefix="/tools")


@router.get("/decisions")
def get_tool_decisions(
    _: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS)),
    user_id: str | None = None,
    decision: str | None = None,
    correlation_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, object]]:
    rows = SecurityPersistenceService().list_policy_decisions(
        filters={"tenant_id": get_current_tenant_id(), "user_id": user_id, "decision": decision, "correlation_id": correlation_id},
        limit=limit,
        offset=offset,
    )
    return [row.__dict__ for row in rows]
