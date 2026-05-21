from __future__ import annotations

import re

BLOCK_PATTERNS: dict[str, re.Pattern[str]] = {
    "api_key": re.compile(r"\b(?:sk|api|xox[baprs])-?[A-Za-z0-9_\-]{16,}\b", re.IGNORECASE),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9\-_.=+/]{20,}\b", re.IGNORECASE),
    "oauth_token": re.compile(r"\b(?:oauth|access|refresh)_token\s*[:=]\s*[\"']?[A-Za-z0-9\-_.=+/]{16,}", re.IGNORECASE),
    "database_url": re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"<>]+", re.IGNORECASE
    ),
    "private_doc_excerpt_placeholder": re.compile(
        r"\b(?:private|confidential|internal)\s+document\s+excerpt\b", re.IGNORECASE
    ),
}


def scan_secret_signals(content: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for finding_type, pattern in BLOCK_PATTERNS.items():
        match = pattern.search(content)
        if match:
            findings.append((finding_type, match.group(0)[:120]))
    return findings
