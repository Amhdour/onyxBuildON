from __future__ import annotations

import os

from onyx.security_layer.opencode_policy.permission_policy import build_permission_policy


def opencode_policy_enabled() -> bool:
    return os.getenv("SECURITY_OPENCODE_POLICY_ENABLED", "false").lower() == "true"


def generate_opencode_permissions(*, dev_mode: bool) -> dict[str, object] | None:
    if not opencode_policy_enabled():
        return None
    return build_permission_policy(dev_mode=dev_mode)
