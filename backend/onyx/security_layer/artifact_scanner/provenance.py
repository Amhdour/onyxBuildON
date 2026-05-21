from __future__ import annotations

import re

EXTERNAL_LINK_PATTERN = re.compile(r"https?://(?!localhost|127\.0\.0\.1)[^\s'\"<>)]+", re.IGNORECASE)


def scan_provenance_signals(content: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    match = EXTERNAL_LINK_PATTERN.search(content)
    if match:
        findings.append(("external_link", match.group(0)[:120]))
    return findings
