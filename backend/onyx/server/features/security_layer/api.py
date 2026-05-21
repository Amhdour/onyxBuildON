from fastapi import APIRouter

from onyx.security_layer.models import PolicyMode

router = APIRouter(prefix="/security-layer")


@router.get("/dashboard")
def security_dashboard() -> dict[str, object]:
    return {
        "enabled_by_default": False,
        "default_mode": PolicyMode.OBSERVE.value,
        "controls": [
            "tool_authorization_gate",
            "opencode_restrictions",
            "sandbox_launch_gate",
            "retrieval_acl_proof",
            "mcp_scope_authorization",
            "artifact_scanner",
        ],
    }
