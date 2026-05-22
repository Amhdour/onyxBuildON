# Security Layer Known Limitations

## Artifact scanner enforcement

Artifact scanning modules and tests are present, but enforcement is currently limited to specific integrated paths. There is no repository-wide mandatory enforcement hook for every artifact export/download/generation path.

## Sandbox guard enforcement

Sandbox guard components are present, but enforcement is currently limited to specific integrated launch paths. There is no global runtime pre-execution enforcement across all code-execution launch paths.

## Local security-layer test prerequisites

To run security-layer tests, use the backend test path and backend dependency lockfiles:

- `pytest -q backend/tests/security_layer`
- dependencies from `backend/requirements/default.txt` (runtime) and `backend/requirements/dev.txt` (pytest/tooling)

If your shell is not already in the project environment, activate `.venv` first:

- `source .venv/bin/activate`

In restricted environments where package installation is blocked, test execution can fail before collection due to missing Python packages (for example `fastapi-users`). This is an environment limitation, not evidence that security-layer checks are absent.


## Retrieval ACL verification scope

Current retrieval ACL verification uses embedded chunk metadata (e.g. `onyx_acl`) as a best-effort signal. It does not perform live DB-backed permission-table verification as source of truth.
