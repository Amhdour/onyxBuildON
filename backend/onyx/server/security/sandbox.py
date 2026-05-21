from fastapi import APIRouter, Depends

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.server.security._state import SANDBOX_GATES
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter(prefix="/sandbox")


@router.get("/gates")
def get_sandbox_gates(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> list[dict[str, object]]:
    tenant_id = get_current_tenant_id()
    return [gate for gate in SANDBOX_GATES if gate.get("tenant_id") == tenant_id]
