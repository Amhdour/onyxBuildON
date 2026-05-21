from fastapi import APIRouter, Depends

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.server.security._state import MCP_EVENTS
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter(prefix="/mcp")


@router.get("/events")
def get_mcp_events(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> list[dict[str, object]]:
    tenant_id = get_current_tenant_id()
    return [event for event in MCP_EVENTS if event.get("tenant_id") == tenant_id]
