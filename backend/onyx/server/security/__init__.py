from fastapi import APIRouter

from onyx.server.security.approvals import router as approvals_router
from onyx.server.security.artifacts import router as artifacts_router
from onyx.server.security.audit import router as audit_router
from onyx.server.security.findings import router as findings_router
from onyx.server.security.launch_gates import router as launch_gates_router
from onyx.server.security.mcp import router as mcp_router
from onyx.server.security.overview import router as overview_router
from onyx.server.security.reports import router as reports_router
from onyx.server.security.retrieval import router as retrieval_router
from onyx.server.security.sandbox import router as sandbox_router
from onyx.server.security.tools import router as tools_router

router = APIRouter(prefix="/admin/security")
router.include_router(overview_router)
router.include_router(approvals_router)
router.include_router(findings_router)
router.include_router(audit_router)
router.include_router(tools_router)
router.include_router(retrieval_router)
router.include_router(mcp_router)
router.include_router(sandbox_router)
router.include_router(artifacts_router)
router.include_router(launch_gates_router)
router.include_router(reports_router)
