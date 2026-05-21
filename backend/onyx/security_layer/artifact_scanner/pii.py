from __future__ import annotations

import re

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
}


def scan_pii_signals(content: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for finding_type, pattern in PII_PATTERNS.items():
        match = pattern.search(content)
        if match:
            findings.append((f"pii_{finding_type}", match.group(0)))
    return findings
