# Security Layer Evidence Index

Date: 2026-05-22

## Evidence Files
- Test command evidence: `docs/security_layer/evidence/test_results.md`
- Demo fixture evidence: `docs/security_layer/evidence/demo_attack_results.md`
- Machine-readable demo report: `docs/security_layer/evidence/demo_attack_report.json`

## Evidence Status Map

### Verified
- Compile validation command completed successfully.
- Demo attack harness command path executed and produced per-scenario status lines + JSON report.

### Not Verified
- Security-layer pytest behavior is not verified due to dependency import failure before collection.
- Demo fixture behavior is not verified due to dependency import failure before collection.

### Blocked
- `fastapi_users` missing blocks collection for `pytest -q tests/security_layer` and the demo fixture scenarios.
- `python-dotenv` missing blocks dotenv-wrapped suite commands documented in `test_results.md`.
- `http://localhost:3000` unavailable blocks Playwright E2E command path documented in `test_results.md`.
