from fastapi import APIRouter, Depends

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.server.security._state import TOOL_DECISIONS
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter(prefix="/tools")


@router.get("/decisions")
def get_tool_decisions(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> list[dict[str, object]]:
    tenant_id = get_current_tenant_id()
    return [decision for decision in TOOL_DECISIONS if decision.get("tenant_id") == tenant_id]
