from __future__ import annotations

from pathlib import Path

from onyx.security_layer.policy.exceptions import PolicyLoadError
from onyx.security_layer.policy.models import PolicyDefinition

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None


def _parse_simple_yaml(text: str) -> dict[str, object]:
    parsed: dict[str, object] = {}
    current_key: str | None = None

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- "):
            if current_key is None:
                raise PolicyLoadError("Malformed yaml: list item without parent key")
            current = parsed.get(current_key)
            if not isinstance(current, list):
                current = []
                parsed[current_key] = current
            current.append(stripped[2:].strip())
            continue

        if ":" not in stripped:
            raise PolicyLoadError(f"Malformed yaml line: {raw_line}")

        key, value = [piece.strip() for piece in stripped.split(":", 1)]
        if not value:
            parsed[key] = []
            current_key = key
            continue

        current_key = key
        lowered = value.lower()
        if lowered == "true":
            parsed[key] = True
        elif lowered == "false":
            parsed[key] = False
        elif value == "[]":
            parsed[key] = []
        else:
            parsed[key] = value

    return parsed


def load_policy_file(path: Path) -> PolicyDefinition:
    try:
        if yaml is not None:
            data = yaml.safe_load(path.read_text())
        else:
            data = _parse_simple_yaml(path.read_text())
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
