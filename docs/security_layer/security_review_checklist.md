# Security Review Checklist — Security Layer

Date: 2026-05-22

## Classification Legend
- Implemented
- Verified
- Not yet verified
- Documented limitation
- Production blocker

## Checklist

### A. Scope & Claims
- [ ] Implementation scope is documented.
- [ ] Claims are constrained to evidence-backed facts.
- [ ] `safe_claims.md` reviewed and approved.

### B. Test Coverage
- [ ] Unit test status classified.
- [ ] External dependency unit test status classified.
- [ ] Integration test status classified.
- [ ] E2E/Playwright status classified.

### C. Demo Attack Coverage
- [ ] Attack scenarios listed.
- [ ] Results captured with timestamps.
- [ ] False-positive/false-negative risk documented.

### D. Blocker Review
- [ ] Each production blocker has owner + remediation plan.
- [ ] Release is blocked until blockers are cleared or risk-accepted.

### E. Auditability
- [ ] Exact commands logged.
- [ ] Exact errors logged.
- [ ] Evidence files version-controlled.
