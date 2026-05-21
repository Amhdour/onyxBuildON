from fastapi import APIRouter, Depends

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.server.security._state import LAUNCH_GATE_RUNS
from onyx.server.security._state import run_launch_gate_engine
from shared_configs.contextvars import get_current_tenant_id

router = APIRouter(prefix="/launch-gates")


@router.get("")
def get_launch_gate_runs(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> list[dict[str, object]]:
    tenant_id = get_current_tenant_id()
    return [run for run in LAUNCH_GATE_RUNS if run.get("tenant_id") == tenant_id]


@router.post("/run")
def run_launch_gate(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> dict[str, object]:
    return run_launch_gate_engine(tenant_id=get_current_tenant_id())
