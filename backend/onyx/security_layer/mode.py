from __future__ import annotations

import os

from onyx.configs import app_configs

_SECURITY_MODES = {"observe", "enforce"}
_TRUE_VALUES = {"1", "true", "yes", "on"}


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in _TRUE_VALUES


def is_security_layer_enabled() -> bool:
    return _env_bool("SECURITY_LAYER_ENABLED", app_configs.SECURITY_LAYER_ENABLED)


def get_security_layer_mode() -> str:
    mode = os.getenv("SECURITY_LAYER_MODE", app_configs.SECURITY_LAYER_MODE)
    mode = str(mode).strip().lower()
    return mode if mode in _SECURITY_MODES else "observe"


def is_observe_mode() -> bool:
    return get_security_layer_mode() == "observe"


def is_enforce_mode() -> bool:
    return get_security_layer_mode() == "enforce"


def should_fail_open() -> bool:
    return is_observe_mode() and _env_bool(
        "SECURITY_LAYER_FAIL_OPEN_IN_OBSERVE",
        app_configs.SECURITY_LAYER_FAIL_OPEN_IN_OBSERVE,
    )


def should_fail_closed() -> bool:
    return is_enforce_mode() and _env_bool(
        "SECURITY_LAYER_FAIL_CLOSED_IN_ENFORCE",
        app_configs.SECURITY_LAYER_FAIL_CLOSED_IN_ENFORCE,
    )
