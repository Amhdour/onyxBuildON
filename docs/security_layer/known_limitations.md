# Security Layer Known Limitations

## Artifact scanner enforcement

Artifact scanning modules and tests are present, but a repository-wide mandatory enforcement hook for every artifact export/download/generation path is not currently wired. Artifact scanning should be treated as module-ready, not globally enforced runtime policy.

## Sandbox guard enforcement

Sandbox guard components are present, but global runtime pre-execution enforcement across all code-execution launch paths is not fully integrated. Sandbox guard should be treated as readiness functionality, not global runtime enforcement.

## Local security-layer test prerequisites

To run security-layer tests, use the backend test path and backend dependency lockfiles:

- `pytest -q backend/tests/security_layer`
- dependencies from `backend/requirements/default.txt` (runtime) and `backend/requirements/dev.txt` (pytest/tooling)

If your shell is not already in the project environment, activate `.venv` first:

- `source .venv/bin/activate`

In restricted environments where package installation is blocked, test execution can fail before collection due to missing Python packages (for example `fastapi-users`). This is an environment limitation, not evidence that security-layer checks are absent.
