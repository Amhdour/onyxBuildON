from __future__ import annotations

import re
from typing import Any

_REDACTED = "[REDACTED]"
_KEYWORDS = (
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "session_token",
    "token",
    "password",
    "passwd",
    "secret",
    "private_key",
    "authorization",
    "cookie",
    "bearer",
)

_BEARER_RE = re.compile(r"bearer\s+[a-z0-9_\-\.]+", re.IGNORECASE)
_OPENAI_RE = re.compile(r"\bsk-[a-zA-Z0-9\-_]{12,}\b")
_AWS_RE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
_JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b")
_GENERIC_SECRET_RE = re.compile(r"(api[_-]?key\s*[:=]\s*\S+|password\s*[:=]\s*\S+)", re.IGNORECASE)
_DEMO_SECRET_RE = re.compile(r"\b(?:demo|fake|test)[_-]?(?:secret|token|key)\b", re.IGNORECASE)


def _needs_redaction_key(key: str) -> bool:
    lowered = key.lower()
    return any(keyword in lowered for keyword in _KEYWORDS)


def _redact_string(value: str) -> str:
    if "-----BEGIN" in value and "PRIVATE KEY-----" in value:
        return _REDACTED

    redacted = value
    for pattern in (_BEARER_RE, _OPENAI_RE, _AWS_RE, _JWT_RE, _GENERIC_SECRET_RE, _DEMO_SECRET_RE):
        redacted = pattern.sub(_REDACTED, redacted)
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
