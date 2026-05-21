from __future__ import annotations

from pathlib import Path

import yaml

from onyx.security_layer.policy.exceptions import PolicyLoadError
from onyx.security_layer.policy.models import PolicyDefinition


def load_policy_file(path: Path) -> PolicyDefinition:
    try:
        data = yaml.safe_load(path.read_text())
    except Exception as e:  # noqa: BLE001
        raise PolicyLoadError(f"Unable to load policy file {path}: {e}") from e

    if not isinstance(data, dict):
        raise PolicyLoadError(f"Policy file {path} must contain an object at root")

    return PolicyDefinition.model_validate(data)


def load_policy_directory(path: Path) -> list[PolicyDefinition]:
    policies: list[PolicyDefinition] = []
    for policy_path in sorted(path.glob("*.yaml")):
        policies.append(load_policy_file(policy_path))
    return policies
