from __future__ import annotations

from onyx.security_layer.decisions.models import RiskLevel


RISK_BY_CLASSIFICATION: dict[str, RiskLevel] = {
    "read_only": RiskLevel.LOW,
    "retrieval": RiskLevel.LOW,
    "web_access": RiskLevel.MEDIUM,
    "file_read": RiskLevel.MEDIUM,
    "file_write": RiskLevel.HIGH,
    "external_write": RiskLevel.HIGH,
    "code_execution": RiskLevel.HIGH,
    "data_export": RiskLevel.HIGH,
    "admin_action": RiskLevel.CRITICAL,
    "credential_access": RiskLevel.CRITICAL,
    "deployment": RiskLevel.CRITICAL,
    "critical": RiskLevel.CRITICAL,
}


def classify_tool_risk(tool_name: str) -> str:
    name = tool_name.lower()

    if any(token in name for token in ["admin", "root", "sudo", "iam"]):
        return "admin_action"
    if any(token in name for token in ["credential", "secret", "token", "vault", "key"]):
        return "credential_access"
    if any(token in name for token in ["deploy", "release", "rollout", "terraform", "k8s"]):
        return "deployment"
    if any(token in name for token in ["python", "shell", "exec", "run", "command"]):
        return "code_execution"
    if any(token in name for token in ["write", "delete", "update", "create", "append"]):
        return "file_write"
    if any(token in name for token in ["upload", "post", "send", "webhook"]):
        return "external_write"
    if any(token in name for token in ["export", "dump"]):
        return "data_export"
    if any(token in name for token in ["open_url", "web", "browser", "http"]):
        return "web_access"
    if any(token in name for token in ["search", "retrieve", "query"]):
        return "retrieval"
    if any(token in name for token in ["read", "view", "list", "get", "fetch"]):
        return "read_only"

    return "critical"
