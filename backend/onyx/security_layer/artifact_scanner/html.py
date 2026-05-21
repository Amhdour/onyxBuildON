from __future__ import annotations

import re

BLOCK_PATTERNS: dict[str, re.Pattern[str]] = {
    "malicious_javascript": re.compile(
        r"<script[^>]*>.*?(?:eval\(|document\.cookie|new\s+Function\(|atob\(|fromCharCode\().*?</script>",
        re.IGNORECASE | re.DOTALL,
    ),
    "tracking_pixel": re.compile(
        r"<img[^>]+(?:width\s*=\s*[\"']?1[\"']?[^>]*height\s*=\s*[\"']?1|height\s*=\s*[\"']?1[\"']?[^>]*width\s*=\s*[\"']?1)[^>]*>",
        re.IGNORECASE,
    ),
    "external_beacon": re.compile(
        r"<(?:img|script|iframe|link)[^>]+(?:src|href)=['\"]https?://(?!localhost|127\.0\.0\.1)[^'\"]+['\"]",
        re.IGNORECASE,
    ),
    "hidden_prompt_injection": re.compile(
        r"<(?:div|span|p)[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^>]*>[^<]*(?:ignore\s+previous|system\s+prompt|override\s+instructions)",
        re.IGNORECASE,
    ),
}

WARN_PATTERNS: dict[str, re.Pattern[str]] = {
    "unknown_embedded_resource": re.compile(r"<(?:object|embed|applet)\b", re.IGNORECASE),
    "external_link": re.compile(r"<a[^>]+href=['\"]https?://(?!localhost|127\.0\.0\.1)[^'\"]+['\"]", re.IGNORECASE),
}

HIDDEN_TEXT_INJECTION_PATTERN = re.compile(
    r"(?:<!--|/\*|#)\s*(?:ignore\s+previous|system\s+prompt|override\s+instructions)",
    re.IGNORECASE,
)


def scan_html_signals(content: str) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    blocked: list[tuple[str, str]] = []
    warned: list[tuple[str, str]] = []

    for finding_type, pattern in BLOCK_PATTERNS.items():
        match = pattern.search(content)
        if match:
            blocked.append((finding_type, match.group(0)[:120]))

    for finding_type, pattern in WARN_PATTERNS.items():
        match = pattern.search(content)
        if match:
            warned.append((finding_type, match.group(0)[:120]))

    return blocked, warned


def scan_hidden_text_prompt_injection(content: str) -> tuple[str, str] | None:
    match = HIDDEN_TEXT_INJECTION_PATTERN.search(content)
    if not match:
        return None
    return ("hidden_prompt_injection", match.group(0)[:120])
