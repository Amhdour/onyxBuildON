# Security Layer Test Results Evidence

Date: 2026-05-22

## Executed Commands and Exact Outcomes

### 1) Backend unit tests
Command:
```bash
source .venv/bin/activate && pytest -xv backend/tests/unit
```

Exit code: `4`

Exact error:
```text
ImportError while loading conftest '/workspace/onyxBuildON/backend/tests/conftest.py'.
backend/tests/conftest.py:7: in <module>
    from onyx.utils.variable_functionality import fetch_versioned_implementation
backend/onyx/utils/variable_functionality.py:8: in <module>
    from onyx.configs.app_configs import API_SERVER_HOST
backend/onyx/configs/app_configs.py:8: in <module>
    from onyx.auth.schemas import AuthBackend
backend/onyx/auth/schemas.py:5: in <module>
    from fastapi_users import schemas
E   ModuleNotFoundError: No module named 'fastapi_users'
```

Status classification:
- Implemented: Yes
- Verified: Command execution + failure mode verified
- Not yet verified: Test suite behavior after dependency installation
- Documented limitation: Missing dependency `fastapi_users`
- Production blocker: Yes (for strict pre-release verification)

---

### 2) External dependency unit tests
Command:
```bash
source .venv/bin/activate && python -m dotenv -f .vscode/.env run -- pytest backend/tests/external_dependency_unit
```

Exit code: `1`

Exact error:
```text
/workspace/onyxBuildON/.venv/bin/python: No module named dotenv
```

Status classification:
- Implemented: Yes
- Verified: Command execution + failure mode verified
- Not yet verified: Actual test run
- Documented limitation: Missing module `dotenv` (python-dotenv)
- Production blocker: Yes (if this suite is release-required)

---

### 3) Integration tests
Command:
```bash
source .venv/bin/activate && python -m dotenv -f .vscode/.env run -- pytest backend/tests/integration
```

Exit code: `1`

Exact error:
```text
/workspace/onyxBuildON/.venv/bin/python: No module named dotenv
```

Status classification:
- Implemented: Yes
- Verified: Command execution + failure mode verified
- Not yet verified: Actual integration behavior
- Documented limitation: Missing module `dotenv` (python-dotenv)
- Production blocker: Yes

---

### 4) Playwright E2E tests
Command:
```bash
cd web && npx playwright test
```

Exit code: `1`

Exact output excerpts:
```text
[global-setup] Waiting for server at http://localhost:3000 ...
[global-setup] ⚠ Still waiting for server after 15s.
  Please verify that both the backend and frontend are running.
  You can start them with: ods compose dev

Error: Onyx is not running at http://localhost:3000. Timed out after 60s waiting for http://localhost:3000 to return 200. Make sure the backend and frontend are running (e.g. `ods compose dev`).
```

Status classification:
- Implemented: Yes
- Verified: Command execution + failure mode verified
- Not yet verified: E2E test behavior with running stack
- Documented limitation: Required server not running/reachable
- Production blocker: Yes (for UI security flow sign-off)
