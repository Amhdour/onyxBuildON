# Production Deployment Checklist — Security Layer

Date: 2026-05-22

## 1) Verification Gate
- [ ] **Implemented**: Required security controls are present in codebase.
- [ ] **Verified**: Unit / integration / E2E security tests pass in release candidate environment.
- [ ] **Not yet verified** items are explicitly listed and accepted by security owner.
- [ ] **Documented limitations** are reviewed and tracked.
- [ ] **Production blockers** are cleared.

## 2) Test Evidence Gate
- [ ] `docs/security_layer/evidence/test_results.md` updated with current run details.
- [ ] `docs/security_layer/evidence/demo_attack_results.md` updated with scenario outcomes.
- [ ] Exact commands and exact errors captured for any failed/missing dependencies.

## 3) Environment & Dependency Gate
- [ ] Python dependencies installed in `.venv` (including `fastapi_users`, `python-dotenv`).
- [ ] Backend/frontend services healthy and reachable.
- [ ] Playwright runtime/browser dependencies available.

## 4) Security Review Gate
- [ ] Security reviewer sign-off recorded.
- [ ] Any high/critical findings resolved or accepted with explicit risk approval.
- [ ] Compensating controls documented for accepted risks.

## 5) Release Decision
- [ ] No unresolved **production blocker** remains.
- [ ] Go/No-Go decision recorded with approver and timestamp.
