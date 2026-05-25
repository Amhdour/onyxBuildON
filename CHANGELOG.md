# Changelog

All notable security-layer and repository workflow changes must be recorded here.

## Unreleased

### Added

- Locked the original baseline on `security-layer-mvp` before security-layer changes.
- Added repository workflow controls for Step 2:
  - CODEOWNERS security review ownership for workflow, documentation, security-layer, retrieval, MCP, sandbox, audit, approval, and policy files.
  - Pull request checklist requiring one control per PR, tests, docs, evidence, CI, review, and branch freshness.
  - CI workflow gates for baseline compile/lint placeholders, PR checklist validation, security review path detection, secret-pattern scanning, and dependency-alert configuration checks.
  - Documentation for repository protection status, manual GitHub settings, and evidence.

### Security

- Direct changes to `main` are disallowed by process. All future work should go through PRs from feature branches.
- Security-sensitive paths require explicit review through CODEOWNERS and PR checklist controls.
- Secret scanning and dependency alerts are represented by repository configuration/evidence files; GitHub Advanced Security toggles must also be verified in the GitHub UI when available.
