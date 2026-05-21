from __future__ import annotations

import json


def export_ndjson(records: list[dict[str, object]]) -> str:
    return "\n".join(json.dumps(r, default=str) for r in records)
