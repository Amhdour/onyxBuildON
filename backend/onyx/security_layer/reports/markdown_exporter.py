from __future__ import annotations


def export_markdown(records: list[dict[str, object]]) -> str:
    if not records:
        return ""
    headers = list(records[0].keys())
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for record in records:
        lines.append("| " + " | ".join(str(record.get(h, "")) for h in headers) + " |")
    return "\n".join(lines)
