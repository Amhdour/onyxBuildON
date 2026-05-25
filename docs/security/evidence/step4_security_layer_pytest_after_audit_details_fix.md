]633;E;echo "# Step 4 Security Layer Pytest After Audit Details Fix";59ee81f5-cba4-4bac-8318-4a2baec347e2]633;C# Step 4 Security Layer Pytest After Audit Details Fix

Date: Mon May 25 11:43:35 UTC 2026
Branch: security-layer-mvp
Commit: 2c31fc327c19ecb38b222a9b92bb8dcacb2d721c

## Command

python -m pytest backend/tests/security_layer -q

## Result

FAIL: security-layer pytest suite executed but did not pass.

## Summary

- 42 passed
- 67 failed
- 2 warnings
- Runtime: 20.46s

## Improvement

The recursive AuditEvent.details schema error is fixed. Tests now execute again.

## Dominant remaining blocker

RuntimeError: Engine not initialized. Must call init_engine first.

## Cause

Security-layer unit tests call AuditService, DecisionService, finding persistence, MCP authorization, sandbox gates, and tool authorization paths that persist to DB-backed services without initializing a SQL engine.

## Next fix direction

Add a test-safe persistence boundary: either initialize a test DB fixture or provide in-memory/no-op persistence services for unit-level security-layer tests.
