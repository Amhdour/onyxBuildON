from __future__ import annotations

import re
from typing import Any

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "api_key": re.compile(r"(?i)(api[_-]?key\s*[=:]\s*[\w-]{12,}|sk-[A-Za-z0-9]{16,})"),
    "bearer_token": re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{12,}"),
    "private_key": re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
    "oauth_token": re.compile(r"(?i)(oauth|refresh|access)_?token\s*[=:]\s*[\w.-]{12,}"),
    "database_url": re.compile(r"(?i)(postgres|mysql|mongodb|redis)(\+\w+)?://[^\s]+"),
    "ssh_path": re.compile(r"(^|\s)(~?/\.ssh/[^\s]+|/home/[^\s]+/\.ssh/[^\s]+)"),
    "aws_path": re.compile(r"(^|\s)(~?/\.aws/[^\s]+|/home/[^\s]+/\.aws/[^\s]+)"),
    "etc_passwd": re.compile(r"/etc/passwd"),
    "printenv": re.compile(r"\bprintenv\b", re.IGNORECASE),
    "env_command": re.compile(r"(^|\s)env(\s|$)", re.IGNORECASE),
    "exfil_destination": re.compile(r"(?i)(pastebin|ngrok|transfer\.sh|webhook|discordapp\.com/api/webhooks|slack\.com/api)") ,
}


def _flatten_to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join([_flatten_to_text(k) + " " + _flatten_to_text(v) for k, v in value.items()])
    if isinstance(value, list | tuple | set):
        return " ".join(_flatten_to_text(v) for v in value)
    return str(value)


def scan_tool_arguments(tool_args: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    arg_text = _flatten_to_text(tool_args)

    for finding_name, pattern in SECRET_PATTERNS.items():
        if pattern.search(arg_text):
            findings.append(finding_name)

    return findings
