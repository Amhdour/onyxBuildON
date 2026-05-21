from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-]+)"),
    re.compile(r"(?i)(oauth[_-]?token\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"ssh-(rsa|ed25519)\s+[A-Za-z0-9+/=]+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(postgres(?:ql)?://)([^\s]+)"),
    re.compile(r"(?i)(password\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)([A-Z0-9_]+\s*=\s*)([^\n]+)"),
]


def redact_text(value: str) -> str:
    redacted = value
    for pattern in _PATTERNS:
        redacted = pattern.sub(lambda m: (m.group(1) if m.lastindex and m.lastindex > 1 else "") + "[REDACTED]", redacted)
    return redacted


def redact_details(details: dict[str, object]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, val in details.items():
        if isinstance(val, str):
            output[key] = redact_text(val)
        else:
            output[key] = val
    return output
