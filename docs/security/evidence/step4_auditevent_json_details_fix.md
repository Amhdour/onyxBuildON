]633;E;echo "# Step 4 AuditEvent JSON Details Fix";e7e9ac59-7df5-4a38-a7f6-a826ada7fff7]633;C# Step 4 AuditEvent JSON Details Fix

Date: Mon May 25 11:38:39 UTC 2026
Branch: security-layer-mvp
Commit before fix: 50ef901

## Root cause

AuditEvent.details accepted only primitive values, but SecurityContext.to_audit_metadata() returns nested JSON-like metadata such as missing_context.

## Fix

Allowed AuditEvent.details to store JSON-style nested metadata.

## Validation command

python -m pytest backend/tests/security_layer -q

## Result

Record the pytest result here.
