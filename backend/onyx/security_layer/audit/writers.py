from __future__ import annotations

import json
from pathlib import Path

from onyx.security_layer.audit.models import AuditEvent


def write_events_json(events: list[AuditEvent], path: Path) -> None:
    payload = [event.model_dump(mode="json") for event in events]
    path.write_text(json.dumps(payload, indent=2))
