from __future__ import annotations

import json


def export_json(records: list[dict[str, object]]) -> str:
    return json.dumps(records, indent=2, default=str)
