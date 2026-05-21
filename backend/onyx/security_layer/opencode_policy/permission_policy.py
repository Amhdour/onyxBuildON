from __future__ import annotations

SECRET_PATH_PATTERNS = [
    "~/.ssh/**",
    "~/.aws/**",
    "~/.config/**",
    "/etc/passwd",
    "/var/run/docker.sock",
    "**/.env",
    "**/*id_rsa*",
    "**/*known_hosts*",
    "**/*credentials*",
    "**/*token*",
]


def build_permission_policy(*, dev_mode: bool) -> dict[str, object]:
    external_directory: str | dict[str, str]
    external_directory = "allow" if dev_mode else {"*": "deny"}
    deny_secret_paths = {pattern: "deny" for pattern in SECRET_PATH_PATTERNS}

    return {
        "bash": "ask",
        "read": {**deny_secret_paths, "*": "ask"},
        "edit": {**deny_secret_paths, "*": "ask"},
        "write": {**deny_secret_paths, "outputs/**": "allow", "*": "deny"},
        "grep": {**deny_secret_paths, "*": "ask"},
        "glob": {**deny_secret_paths, "*": "ask"},
        "list": "allow",
        "lsp": "allow",
        "patch": "allow",
        "question": "allow",
        "skill": "ask",
        "webfetch": "ask",
        "external_directory": external_directory,
    }
