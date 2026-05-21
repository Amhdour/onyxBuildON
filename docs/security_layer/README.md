# Security Layer MVP Documentation

## 1. What this is
This documentation describes the **MVP security layer** for Onyx runtime operations. It defines how policy decisions are made, enforced, and audited across tool usage, retrieval, MCP access, artifact handling, and launch-time controls.

## 2. MVP scope
The MVP focuses on baseline, high-impact guardrails:
- Policy-driven allow/deny decisions
- Runtime enforcement hooks
- Audit and findings generation
- Launch-gate validation for unsafe configurations
- Admin and CI visibility via reports/artifacts

## 3. What it protects
The security layer protects:
- Tool execution boundaries
- Sensitive source and secret paths in OpenCode workflows
- Sandbox safety posture at launch
- Retrieval access control boundaries (ACL)
- MCP scope and authorization boundaries
- Build/runtime artifacts from obvious secret leakage

## 4. Architecture
See [architecture.md](./architecture.md) for the layered MVP architecture and data flow.

## 5. Policy modes
MVP supports three policy operating modes:
- **Observe**: record decisions/findings without hard blocking
- **Warn**: allow operation but emit high-visibility warnings and findings
- **Enforce**: block policy-violating actions

## 6. Tool authorization
Tool authorization evaluates:
- Tool identity and risk classification
- Caller context (tenant, user, role, session)
- Requested action parameters
- Mode-specific policy outcomes (observe/warn/enforce)

Expected behavior:
- Low-risk tools are allowed when scope is valid.
- High-risk tools require explicit policy allow.
- Unauthorized or out-of-scope requests are denied in enforce mode.

## 7. OpenCode restrictions
OpenCode restrictions block or constrain:
- Reads from protected secret-bearing paths
- Direct prompt-time exfiltration attempts from sensitive files
- Disallowed execution patterns that bypass declared policy boundaries

## 8. Sandbox launch gates
Launch gates validate sandbox config before runtime launch, including:
- Unsafe privilege escalation flags
- Disallowed network/storage exposure profiles
- Missing mandatory security toggles

Unsafe combinations fail launch with machine-readable evidence.

## 9. Retrieval ACL proof
Retrieval requests must include proofable ACL context:
- Principal identity
- Tenant boundary
- Document/object scope authorization
- Optional delegated permissions context

Unauthorized retrieval attempts are denied and logged.

## 10. MCP authorization
MCP access is controlled by scope-aware authorization:
- Explicit server/scope allowlist checks
- Deny on attempted scope expansion/bypass
- Audit records for all decisions

## 11. Artifact scanning
MVP artifact scanning detects and blocks obvious leaks in generated outputs:
- API key-like patterns
- Credentials in plaintext config snippets
- Known secret token formats (baseline signatures)

Blocked artifacts produce findings and remediation guidance.

## 12. Audit events
Each security decision emits an audit event with:
- Event type and timestamp
- Actor, tenant, and request context
- Policy decision (allow/deny/warn)
- Rule IDs and rationale
- Correlation IDs for traceability

## 13. Findings
Findings are generated for policy violations and high-risk warnings. Each finding includes:
- Severity
- Category
- Evidence references
- Suggested remediation
- Link to related audit events

## 14. Launch-gate reports
Launch-gate reports summarize pass/fail checks with:
- Gate results and failed checks
- Configuration evidence
- Policy version
- Recommended fixes

## 15. Admin UI
Admin UI surfaces:
- Policy mode and status
- Recent denials/warnings
- Findings trends
- Launch-gate outcomes
- Drill-down to event-level evidence

## 16. CI workflow
CI integration runs security checks and publishes artifacts:
- Policy decision summaries
- Findings report
- Launch-gate report
- Optional quality gate fail on enforce-level violations

## 17. Demo attacks
See [demo_script.md](./demo_script.md) for step-by-step demo scenarios:
- Allowed normal call
- Denied high-risk call
- OpenCode secret read block
- Launch-gate failures
- Retrieval/MCP denial paths
- Artifact leak prevention

## 18. How to run tests
Suggested MVP test commands:
```bash
pytest -xv backend/tests/unit
python -m dotenv -f .vscode/.env run -- pytest backend/tests/external_dependency_unit
python -m dotenv -f .vscode/.env run -- pytest backend/tests/integration
```

## 19. How to generate reports
Typical report generation flow:
1. Run policy/audit test suite.
2. Run launch-gate checks against target sandbox configs.
3. Run artifact scans against produced artifacts.
4. Export generated JSON/HTML artifacts from CI outputs.

See your pipeline/security job for exact output directories and retention settings.

## 20. Known limitations
See [known_limitations.md](./known_limitations.md).

## 21. Phase 2 backlog
See [phase_2_backlog.md](./phase_2_backlog.md).
