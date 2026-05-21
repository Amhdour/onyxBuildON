from __future__ import annotations

import json


def export_sarif(records: list[dict[str, object]]) -> str:
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Onyx Security Layer"}},
                "results": [
                    {
                        "ruleId": str(record.get("policy_id", "unknown")),
                        "level": str(record.get("severity", "warning")),
                        "message": {"text": str(record.get("title", ""))},
                    }
                    for record in records
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2)
