#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

run_cmd() {
  echo
  echo "================================================================"
  echo "RUNNING: $*"
  echo "================================================================"
  set +e
  "$@"
  code=$?
  set -e
  echo "EXIT CODE: $code"
}

if [[ -f ".venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
else
  echo "WARNING: .venv/bin/activate not found"
fi

run_cmd pytest -xv backend/tests/unit
run_cmd python -m dotenv -f .vscode/.env run -- pytest backend/tests/external_dependency_unit
run_cmd python -m dotenv -f .vscode/.env run -- pytest backend/tests/integration
run_cmd bash -lc 'cd web && npx playwright test'

echo

echo "Verification run complete. Update docs/security_layer/evidence/test_results.md with exact outputs."
