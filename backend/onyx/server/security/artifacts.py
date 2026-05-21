from fastapi import APIRouter, Depends

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.server.security._state import ARTIFACT_SCANS
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter(prefix="/artifacts")


@router.get("/scans")
def get_artifact_scans(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> list[dict[str, object]]:
    tenant_id = get_current_tenant_id()
    return [scan for scan in ARTIFACT_SCANS if scan.get("tenant_id") == tenant_id]
