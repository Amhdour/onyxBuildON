# Demo Attack Results Evidence

Date: 2026-05-22

## Command
```bash
bash scripts/security_layer/run_demo_attacks.sh
```

Exit code: `1`

## Expected Outcomes
- Script remains non-destructive.
- Script executes safe fixture tests for:
  - tool authorization deny fixture
  - approval replay fixture
  - MCP missing-scope or missing-context fixture
  - retrieval enforce/observe fixture
  - artifact scanner secret-detection fixture
  - sandbox unsafe-config fixture
- Script writes machine-readable JSON report.
- Script runs a dependency preflight before scenario execution.
- If dependencies are missing, script prints exact blocker, marks scenarios blocked, and exits non-zero without running scenario-by-scenario pytest.

## Observed Result
```text
BLOCKER: missing_dependency (fastapi_users)
[tool_authorization_deny] status=blocked exit_code=1
[approval_replay_fixture] status=blocked exit_code=1
[mcp_missing_scope_or_context] status=blocked exit_code=1
[retrieval_enforce_observe] status=blocked exit_code=1
[artifact_scanner_secret_detection] status=blocked exit_code=1
[sandbox_unsafe_config] status=blocked exit_code=1
JSON report written to docs/security_layer/evidence/demo_attack_report.json
```

## Verification Classification
- Implemented: Yes (safe executable fixture runner + JSON report output)
- Verified: Command path verified. Scenario behavior not verified because dependency import failed before collection.
- Not yet verified: Scenario behavior assertions after dependency installation
- Documented limitation: Missing `fastapi_users`
- Production blocker: Yes, until blocked scenarios are re-run in a provisioned environment
