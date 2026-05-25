# Onyx Agent Runtime Security Layer — Step 1 Baseline Lock

Date recorded: 2026-05-25
Repository: `Amhdour/onyxBuildON`
Baseline branch: `security-layer-mvp`
Default branch source: `main`
Baseline source commit: `a75621ff6845222b1339dc1caa4ed91da508fe49`
Baseline source commit message: `Merge pull request #43 from Amhdour/codex/complete-baseline-documentation-for-onyx-agent`

## Purpose

This file locks the original GitHub baseline used before continuing the security-layer MVP work. It records the reference commit, observed structure, setup/test assumptions, known evidence, and current security gaps. No application code is changed by this baseline-lock commit.

## Baseline actions completed

1. Confirmed connected GitHub account: `Amhdour`.
2. Located target repository: `Amhdour/onyxBuildON`.
3. Confirmed repository default branch: `main`.
4. Created branch `security-layer-mvp` from commit `a75621ff6845222b1339dc1caa4ed91da508fe49`.
5. Preserved project code untouched.
6. Refreshed this `BASELINE_COMMIT.md` on `security-layer-mvp` to match the locked GitHub baseline.

## Original project structure summary

Observed high-level project structure and areas from repository files and the previous baseline record:

- `backend/` — backend application, services, workers, tests, model server, and enterprise modules.
- `web/` — Next.js / React / TypeScript frontend and frontend tests.
- `desktop/` — desktop app assets.
- `deployment/` — Docker Compose, Helm, Terraform, ECS, and deployment assets.
- `docs/` — documentation and existing security-layer documentation/evidence.
- `scripts/`, `tools/`, `examples/`, `demo/` — operational scripts, tooling, examples, and demo assets.

## Observed product/security-relevant capabilities

The README identifies Onyx as an open-source AI platform for LLM applications with RAG, web search, code execution, file creation, deep research, artifacts, actions, and MCP-related capabilities. These capabilities are the relevant baseline surfaces for the planned security layer.

## Original setup and test commands recorded from prior baseline evidence

The existing baseline evidence recorded the following intended commands or command families:

- `source .venv/bin/activate`
- `python -m dotenv -f .vscode/.env run -- pytest backend/tests/external_dependency_unit`
- `python -m dotenv -f .vscode/.env run -- pytest backend/tests/integration`
- `pytest -xv backend/tests/unit`
- `npm test` from `web/package.json`
- `npx playwright test <TEST_NAME>`

## Original passing checks recorded from prior baseline evidence

The previous baseline record stated that repository metadata capture succeeded and environment info commands succeeded for Python, Node, npm, and pytest.

## Original failing checks recorded from prior baseline evidence

The previous baseline record stated that `pytest -xv backend/tests/unit --collect-only` failed with:

```text
ModuleNotFoundError: No module named 'fastapi_users'
Exit code: 4
```

## Checks not independently executed in this GitHub connector step

This GitHub baseline-lock operation did not run the test suite, dependency installation, backend startup, frontend startup, Playwright, or demo attacks. The connector operation can update repository files and branches, but it does not provide a live Codespace shell for executing project commands.

## Original security gaps and unknowns

- A green baseline test state is not confirmed in this operation.
- Runtime security-layer validation is not confirmed in this operation.
- Dependency completeness is not confirmed in this operation.
- Cross-tenant retrieval isolation is not confirmed in this operation.
- Tool authorization enforcement is not confirmed in this operation.
- MCP hardening is not confirmed in this operation.
- Artifact scanning/release enforcement is not confirmed in this operation.
- Sandbox execution enforcement is not confirmed in this operation.
- Audit trail completeness is not confirmed in this operation.
- CI branch protection and required checks are not confirmed in this operation.

## Assumptions

- `Amhdour/onyxBuildON` is the intended repository for this baseline-lock request.
- `main` at `a75621ff6845222b1339dc1caa4ed91da508fe49` is the GitHub baseline source for this step.
- Existing code should remain untouched until the baseline is recorded.
- Any previous evidence under `docs/security/evidence/` should be treated as historical evidence unless re-run in the current environment.

## Next required manual/Codespace validation

1. Open `security-layer-mvp` in Codespaces.
2. Run environment version checks.
3. Install dependencies without patching application code.
4. Run backend compile/test collection.
5. Run backend tests.
6. Run frontend lint/typecheck/tests.
7. Run Playwright smoke tests.
8. Run existing demo attacks, if present.
9. Save outputs under `docs/security/evidence/`.
10. Update `docs/security/baseline_validation.md` with exact pass/fail evidence.

## Non-claim statement

This baseline lock does not claim production readiness, enterprise readiness, passing tests, complete security coverage, or successful launch-gate status. It only records the repository baseline reference before continuing implementation.
