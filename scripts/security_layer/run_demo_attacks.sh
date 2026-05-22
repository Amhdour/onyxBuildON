#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
REPORT_PATH="docs/security_layer/evidence/demo_attack_report.json"
TMP_RESULTS="$(mktemp)"

if [[ -f ".venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

if ! command -v pytest >/dev/null 2>&1; then
  echo "BLOCKER: pytest not found in current environment"
  exit 2
fi

SCENARIOS=(
  "tool_authorization_deny|backend/tests/security_layer/test_tool_authorization.py::test_admin_action_denied"
  "approval_replay_fixture|backend/tests/security_layer/test_tool_authorization.py::test_approval_replay_hash_expired_denied"
  "mcp_missing_scope_or_context|backend/tests/security_layer/test_mcp_authorization.py::test_missing_scope_denies_action"
  "retrieval_enforce_observe|backend/tests/security_layer/test_retrieval_acl_proof.py::test_private_denied_chunk_denied"
  "artifact_scanner_secret_detection|backend/tests/security_layer/test_artifact_scanner.py::test_api_key_blocked"
  "sandbox_unsafe_config|backend/tests/security_layer/test_sandbox_gates.py::test_docker_socket_exposed_fails"
)

missing_dependency=""
all_pass=true

for scenario in "${SCENARIOS[@]}"; do
  name="${scenario%%|*}"
  test_target="${scenario##*|}"

  set +e
  output="$(pytest -q "$test_target" 2>&1)"
  code=$?
  set -e

  status="failed"
  blocker=""
  verified=false

  if [[ $code -eq 0 ]]; then
    status="passed"
    verified=true
  elif [[ "$output" == *"ModuleNotFoundError"* ]] || [[ "$output" == *"ImportError while loading conftest"* ]]; then
    status="blocked"
    blocker="dependency_import_failed_before_collection"
    all_pass=false
    if [[ -z "$missing_dependency" ]]; then
      missing_dependency="$(printf '%s\n' "$output" | rg -o "No module named '[^']+'" -m 1 || true)"
    fi
  else
    all_pass=false
  fi

  echo "[$name] status=$status exit_code=$code"

  python - <<PY >> "$TMP_RESULTS"
import json
print(json.dumps({
  "scenario": "$name",
  "test_target": "$test_target",
  "status": "$status",
  "exit_code": $code,
  "verified": "$verified" == "true",
  "blocker": "$blocker" if "$blocker" else None,
  "output": """$output""",
}))
PY
done

python - <<PY
import json
from pathlib import Path
lines = Path("$TMP_RESULTS").read_text(encoding="utf-8").splitlines()
report = {
  "timestamp_utc": "$TIMESTAMP",
  "command": "bash scripts/security_layer/run_demo_attacks.sh",
  "results": [json.loads(line) for line in lines if line.strip()],
}
Path("$REPORT_PATH").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
PY

rm -f "$TMP_RESULTS"

if [[ -n "$missing_dependency" ]]; then
  echo "BLOCKER: $missing_dependency"
fi

echo "JSON report written to $REPORT_PATH"

if [[ "$all_pass" == "true" ]]; then
  exit 0
fi

exit 1
