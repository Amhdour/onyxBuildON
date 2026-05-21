from __future__ import annotations

import csv
import io


def export_csv(records: list[dict[str, object]]) -> str:
    if not records:
        return ""
    headers = list(records[0].keys())
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=headers)
    writer.writeheader()
    writer.writerows(records)
    return out.getvalue()
