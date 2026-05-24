# Onyx Agent Runtime Security Layer — Step 1 Baseline Lock

Date (UTC): 2026-05-24

## Repository identity
- Current branch: `work`
- Current commit hash: `5791e31c91e9b2fc90721fa521f0167f51a34104`

## Project structure summary
High-level directories observed at baseline include:
- `backend/` (FastAPI services, Celery workers, tests, model server, EE modules)
- `web/` (Next.js/React TypeScript frontend + tests)
- `desktop/` (Tauri desktop app)
- `deployment/` (Docker Compose, Helm, Terraform, ECS deployment assets)
- `docs/` (developer, craft, security-layer docs)
- `scripts/`, `tools/`, `examples/`, `demo/`

Raw directory snapshot: `docs/security/evidence/baseline_repo_snapshot.txt`.

## Detected backend stack
Detected from dependency manifests and repo layout:
- Python backend (FastAPI)
- SQLAlchemy + Alembic
- Celery workers
- Redis client/runtime usage
- LiteLLM + LangChain Core
- Pytest test framework

Evidence: `docs/security/evidence/baseline_stack_detection.txt`.

## Detected frontend stack
Detected from `web/package.json`:
- Next.js application (`next dev/build/start` scripts)
- React 18 + TypeScript
- Jest unit tests
- Playwright E2E tests
- Storybook support

Evidence: `docs/security/evidence/baseline_stack_detection.txt`.

## Detected database / vector / search dependencies
Detected from project docs + deployment artifacts + dependency hints:
- PostgreSQL (primary relational DB)
- Redis (cache/coordination/queue backend)
- Vespa (vector/search engine)
- Model server services for inference/indexing
- Optional OpenSearch dashboard artifacts in Helm dashboards

Evidence: `docs/security/evidence/baseline_stack_detection.txt` and repository deployment files.

## Detected setup commands (as baseline assumptions)
These were identified from AGENTS guidance and common repo conventions; not all were executed:
- `source .venv/bin/activate`
- `python -m dotenv -f .vscode/.env run -- pytest backend/tests/external_dependency_unit`
- `python -m dotenv -f .vscode/.env run -- pytest backend/tests/integration`
- `pytest -xv backend/tests/unit`
- `npx playwright test <TEST_NAME>`

## Detected test commands
- Backend unit tests: `pytest -xv backend/tests/unit`
- Backend external dependency tests: `python -m dotenv -f .vscode/.env run -- pytest backend/tests/external_dependency_unit`
- Backend integration tests: `python -m dotenv -f .vscode/.env run -- pytest backend/tests/integration`
- Frontend unit tests: `npm test` (from `web/package.json`)
- Frontend E2E tests: `npx playwright test <TEST_NAME>`

## Commands actually executed
1. `pwd; rg --files -g 'AGENTS.md'`
2. `git branch --show-current; git rev-parse HEAD; git status --short; rg --files | head -n 200`
3. Snapshot capture to `docs/security/evidence/baseline_repo_snapshot.txt`
4. Stack detection capture to `docs/security/evidence/baseline_stack_detection.txt`
5. Environment checks capture to `docs/security/evidence/baseline_env_checks.txt`
6. `source .venv/bin/activate && pytest -xv backend/tests/unit --collect-only`
   - stdout/stderr saved to `docs/security/evidence/unit_collect_only.txt`
   - exit code saved to `docs/security/evidence/unit_collect_only.exitcode`

## Passing checks
- Repository metadata checks succeeded (branch/commit/status capture).
- Environment info commands succeeded (`python --version`, `node --version`, `npm --version`, `pytest --version`).

## Failing checks
- `pytest -xv backend/tests/unit --collect-only` failed with:
  - `ModuleNotFoundError: No module named 'fastapi_users'`
  - Exit code: `4`

Evidence: `docs/security/evidence/unit_collect_only.txt` and `docs/security/evidence/unit_collect_only.exitcode`.

## Skipped checks (with reason)
- Full backend unit/external-dependency/integration suites were not run in this baseline-lock step to avoid behavior-altering setup/fix work and long-running environment-dependent execution.
- Frontend Jest/Playwright suites were not run in this step for the same reason.

## Original security gaps (baseline observation only; no fixes)
Initial baseline-level gaps/unknowns observed from this run:
- No validated green test baseline yet in this environment due to dependency/import failure during unit test collection.
- No runtime security-layer validation artifacts yet beyond baseline evidence capture.
- Security posture is unverified for this environment until dependency completeness and test execution are validated.

## Assumptions
- The checked-out state at commit `5791e31c91e9b2fc90721fa521f0167f51a34104` is the official baseline for the security-layer project kickoff.
- The local `.venv` should be the intended Python runtime, but dependency completeness is currently uncertain.
- AGENTS-documented commands reflect intended test paths, but may require additional local setup not performed in this step.

## Next baseline validation steps
1. Validate Python dependency installation in `.venv` (without code changes).
2. Re-run unit-test collection and then targeted backend test commands.
3. Run frontend `npm test` and targeted Playwright smoke tests when environment is ready.
4. Archive all command outputs into `docs/security/evidence/` for traceability.
5. Keep this baseline commit immutable as the reference point before any security-layer implementation begins.

## Non-claim statement
This baseline documentation does **not** claim production readiness, feature completeness, or passing test status.
