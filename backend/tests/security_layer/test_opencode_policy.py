from __future__ import annotations

from onyx.server.features.build.sandbox.util.opencode_config import build_opencode_config


def _config(enabled: bool) -> dict:
    import os

    os.environ["SECURITY_OPENCODE_POLICY_ENABLED"] = "true" if enabled else "false"
    return build_opencode_config(provider="openai", model_name="gpt-4o")


def test_bash_requires_approval() -> None:
    cfg = _config(True)
    assert cfg["permission"]["bash"] == "ask"


def test_secret_path_read_denied() -> None:
    cfg = _config(True)
    assert cfg["permission"]["read"]["~/.ssh/**"] == "deny"


def test_write_limited_to_outputs() -> None:
    cfg = _config(True)
    assert cfg["permission"]["write"]["outputs/**"] == "allow"
    assert cfg["permission"]["write"]["*"] == "deny"


def test_docker_command_denied() -> None:
    cfg = _config(True)
    assert cfg["permission"]["bash"] == "ask"


def test_kubectl_command_denied() -> None:
    cfg = _config(True)
    assert cfg["permission"]["bash"] == "ask"


def test_terraform_apply_denied() -> None:
    cfg = _config(True)
    assert cfg["permission"]["bash"] == "ask"


def test_env_denied() -> None:
    cfg = _config(True)
    assert cfg["permission"]["bash"] == "ask"


def test_printenv_denied() -> None:
    cfg = _config(True)
    assert cfg["permission"]["bash"] == "ask"


def test_unknown_domain_webfetch_requires_approval() -> None:
    cfg = _config(True)
    assert cfg["permission"]["webfetch"] == "ask"


def test_disabled_flag_preserves_existing_behavior() -> None:
    cfg = _config(False)
    assert cfg["permission"]["webfetch"] == "allow"
    assert cfg["permission"]["bash"]["*"] == "allow"
