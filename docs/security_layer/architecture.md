# Security Layer MVP Architecture

## Layered architecture

1. **Onyx runtime**
   - Origin of user-initiated and system-initiated actions.
   - Emits operation requests (tool, retrieval, MCP, artifact, launch).

2. **Security context builder**
   - Normalizes principal/session/tenant metadata.
   - Adds request attributes, resource metadata, and execution environment details.

3. **Policy engine**
   - Evaluates normalized security context against configured rules.
   - Produces deterministic result for current mode (observe/warn/enforce).

4. **Decision**
   - Canonical outcome object: allow/deny/warn, rule IDs, rationale, confidence, and correlation ID.

5. **Audit event**
   - Persisted event stream entry for every evaluated decision.
   - Contains immutable context snapshot and outcome.

6. **Finding**
   - Derived from denials or high-risk warnings.
   - Adds severity, category, remediation, and lifecycle state.

7. **Enforcement**
   - Runtime hook that blocks, warns, redacts, or allows operation based on decision + mode.

8. **Launch-gate evidence**
   - Structured pass/fail records for pre-launch sandbox checks.
   - Attachments for failed checks and fix recommendations.

9. **Admin UI**
   - Operator-facing layer for policy state, findings triage, and report review.

## Data flow (high level)
Onyx runtime request -> security context builder -> policy engine -> decision -> enforcement + audit event -> optional finding -> launch-gate evidence (when applicable) -> admin UI + CI artifacts.
