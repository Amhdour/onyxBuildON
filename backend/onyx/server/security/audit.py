from fastapi import APIRouter, Depends

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.server.security._state import AUDIT_EVENTS
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter()


@router.get("/audit")
def get_audit_events(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> list[dict[str, object]]:
    tenant_id = get_current_tenant_id()
    return [event.model_dump(mode="json") for event in AUDIT_EVENTS if event.tenant_id == tenant_id]
