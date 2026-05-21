from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse

from onyx.auth.permissions import require_permission
from onyx.db.enums import Permission
from onyx.db.models import User
from onyx.server.security._state import REPORT_DIR

router = APIRouter(prefix="/reports")


@router.get("")
def list_reports(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> list[str]:
    if not REPORT_DIR.exists():
        return []
    return sorted([f.name for f in REPORT_DIR.iterdir() if f.is_file()])


@router.get("/launch_gate_report.json")
def get_launch_gate_json_report(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> FileResponse:
    return FileResponse(path=Path(REPORT_DIR / "launch_gate_report.json"))


@router.get("/launch_gate_report.md")
def get_launch_gate_md_report(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> FileResponse:
    return FileResponse(path=Path(REPORT_DIR / "launch_gate_report.md"))


@router.get("/security_findings.sarif")
def get_security_findings_sarif_report(_: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS))) -> FileResponse:
    return FileResponse(path=Path(REPORT_DIR / "security_findings.sarif"))
