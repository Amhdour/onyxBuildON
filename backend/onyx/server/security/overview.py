from fastapi import APIRouter, Depends

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.server.security._state import build_overview
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter()


@router.get("/overview")
def get_security_overview(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> dict[str, object]:
    return build_overview(tenant_id=get_current_tenant_id())
