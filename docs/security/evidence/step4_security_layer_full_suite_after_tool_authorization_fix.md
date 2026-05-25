# Step 4 Security Layer Full Suite After Tool Authorization Fix

Date: Mon May 25 17:04:57 UTC 2026
Branch: security-layer-mvp
Commit before evidence: 9c9363cc6c07f585b80befd0d57f550bf2cd0150

## Command

source .venv/bin/activate
python -m pytest backend/tests/security_layer -q

## Result

FAIL: full security-layer pytest suite executed but did not fully pass.

## Summary

- 82 passed
- 27 failed
- 2 warnings
- Runtime: 5.02s

## Improvement

- Previous full-suite result: 66 passed, 43 failed
- New full-suite result: 82 passed, 27 failed
- Net improvement: 16 additional passing tests

## Remaining failure groups

- Demo attack expectations still mismatch in prompt-injection/tool-call and opencode secret-read tests.
- MCP authorization still denies some search/missing-context cases where tests expect allow/observe behavior.
- Policy engine defaults to deny when tests expect default allow without matching rules.
- Redaction does not redact token=abc in nested string payloads.
- Retrieval ACL proof tests fail during InferenceChunk construction because source_links, image_file_id, and section_continuation are now required fields.

## Warnings

- Unknown pytest config option: asyncio_default_fixture_loop_scope
- Unknown pytest config option: env_files

## Next recommended focus

Fix the retrieval ACL proof fixture/model compatibility first because it accounts for most remaining failures and blocks retrieval-guard behavioral validation.
