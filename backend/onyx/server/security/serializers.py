from __future__ import annotations

from datetime import datetime
from typing import Any

from onyx.security_layer.redaction import redact_security_payload


def serialize_security_row(row: object) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in vars(row).items():
        if key.startswith("_"):
            continue
        if isinstance(value, datetime):
            out[key] = value.isoformat()
        else:
            out[key] = value
    return redact_security_payload(out)
