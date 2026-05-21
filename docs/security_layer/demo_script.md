# Security Layer MVP Demo Script

## Preconditions
- Security layer enabled.
- Policy mode toggle available (observe/warn/enforce).
- Test tenant, user principal, and demo data ready.
- Admin UI + CI artifact viewer reachable.

## 1) Show normal tool call allowed
- Execute a known low-risk tool call in allowed scope.
- Confirm decision = allow.
- Capture corresponding audit event.

## 2) Show high-risk tool call denied
- Attempt a high-risk tool call without explicit approval.
- Confirm decision = deny in enforce mode.
- Show finding generated.

## 3) Show OpenCode secret read blocked
- Attempt read of protected secret-bearing path.
- Confirm block response and redaction behavior.
- Show linked audit event + finding.

## 4) Show unsafe sandbox config fails launch gate
- Submit sandbox launch with intentionally unsafe config.
- Confirm launch blocked.
- Open launch-gate evidence report and failed checks.

## 5) Show unauthorized retrieval denied
- Request retrieval for a document outside caller ACL.
- Confirm deny decision and retrieval ACL proof failure reason.

## 6) Show MCP scope bypass denied
- Attempt MCP action with expanded/unauthorized scope.
- Confirm deny and rule ID in decision output.

## 7) Show artifact secret leak blocked
- Generate artifact containing test secret signature.
- Run artifact scanning.
- Confirm block and finding creation.

## 8) Show audit events
- Open audit stream/log viewer.
- Filter by correlation ID from prior steps.
- Demonstrate end-to-end traceability.

## 9) Show findings
- Open findings list.
- Highlight severities, categories, and remediation guidance.

## 10) Show launch-gate report
- Open latest launch-gate report.
- Review pass/fail checks and evidence attachments.

## 11) Show admin dashboard
- Navigate policy mode, findings trends, denial counts.
- Drill into one event and related finding.

## 12) Show CI artifacts
- Open CI run artifacts.
- Show exported security reports: decisions, findings, launch-gate evidence.
