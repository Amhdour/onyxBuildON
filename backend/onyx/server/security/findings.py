from fastapi import APIRouter, Depends

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.server.security._state import FINDINGS
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter()


@router.get("/findings")
def get_findings(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> list[dict[str, object]]:
    tenant_id = get_current_tenant_id()
    return [f.model_dump(mode="json") for f in FINDINGS if f.tenant_id == tenant_id]
