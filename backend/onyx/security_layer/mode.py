from __future__ import annotations

from onyx.configs import app_configs

_SECURITY_MODES = {"observe", "enforce"}


def is_security_layer_enabled() -> bool:
    return app_configs.SECURITY_LAYER_ENABLED


def get_security_layer_mode() -> str:
    mode = app_configs.SECURITY_LAYER_MODE
    return mode if mode in _SECURITY_MODES else "observe"


def is_observe_mode() -> bool:
    return get_security_layer_mode() == "observe"


def is_enforce_mode() -> bool:
    return get_security_layer_mode() == "enforce"


def should_fail_open() -> bool:
    return is_observe_mode() and app_configs.SECURITY_LAYER_FAIL_OPEN_IN_OBSERVE


def should_fail_closed() -> bool:
    return is_enforce_mode() and app_configs.SECURITY_LAYER_FAIL_CLOSED_IN_ENFORCE
