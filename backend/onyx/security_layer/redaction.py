from __future__ import annotations

import re
from typing import Any

_REDACTED = "[REDACTED]"
_KEYWORDS = (
    "api_key",
    "apikey",
    "token",
    "password",
    "secret",
    "private_key",
    "authorization",
    "cookie",
    "session",
    "bearer",
)

_BEARER_RE = re.compile(r"bearer\s+[a-z0-9_\-\.]+", re.IGNORECASE)
_GENERIC_SECRET_RE = re.compile(r"(sk-[a-z0-9\-]{8,}|api[_-]?key\s*[:=]\s*\S+)", re.IGNORECASE)


def _needs_redaction_key(key: str) -> bool:
    lowered = key.lower()
    return any(keyword in lowered for keyword in _KEYWORDS)


def _redact_string(value: str) -> str:
    redacted = _BEARER_RE.sub(_REDACTED, value)
    redacted = _GENERIC_SECRET_RE.sub(_REDACTED, redacted)
    if "-----BEGIN" in value and "PRIVATE KEY-----" in value:
        return _REDACTED
    return redacted


def redact_security_payload(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if _needs_redaction_key(key):
                out[key] = _REDACTED
            else:
                out[key] = redact_security_payload(item)
        return out
    if isinstance(value, list):
        return [redact_security_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_security_payload(item) for item in value)
    if isinstance(value, str):
        return _redact_string(value)
    return value
