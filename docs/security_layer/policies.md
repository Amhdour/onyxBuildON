# Security Layer MVP Policies

## Policy model
Each policy rule should define:
- Rule ID
- Target surface (tool/retrieval/MCP/OpenCode/artifact/launch)
- Match conditions (principal, scope, resource, risk tags)
- Mode behavior (observe, warn, enforce)
- Rationale and remediation text

## Default MVP policy families

### 1) Tool authorization policy
- Allow explicitly approved low-risk tools in tenant scope.
- Deny high-risk tools unless explicitly approved.
- Require context completeness (principal + tenant + operation metadata).

### 2) OpenCode restrictions policy
- Deny reads from protected secret paths.
- Deny exfiltration-oriented prompts against sensitive sources.
- Warn on borderline risky read patterns in warn mode.

### 3) Sandbox launch-gate policy
- Deny unsafe privilege/network/storage config combinations.
- Require minimum secure runtime flags.
- Emit launch evidence for pass and fail states.

### 4) Retrieval ACL policy
- Require document/object ACL match for requesting principal.
- Deny cross-tenant access.
- Deny missing/invalid ACL proof contexts.

### 5) MCP authorization policy
- Enforce explicit scope allowlist.
- Deny scope escalation attempts.
- Require tenant-authorized server binding.

### 6) Artifact scanning policy
- Detect and block obvious secret patterns.
- Attach evidence snippet fingerprints (not raw full secret) to findings.
- Allow clean artifacts and log scan pass metadata.
