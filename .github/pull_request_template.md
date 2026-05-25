## Description

<!-- Provide a brief description of the change. Keep each PR scoped to one control or one clearly related workflow change. -->

## Control scope

- [ ] This PR changes exactly one control or one clearly related control group.
- [ ] No unrelated refactors or cleanup are included.
- [ ] Security-layer files were reviewed when touched.

## Required evidence

- [ ] Tests were added or updated with the change.
- [ ] Documentation was added or updated with the change.
- [ ] Evidence was added or updated under `docs/security/evidence/` when relevant.
- [ ] `CHANGELOG.md` was updated.

## Repository workflow gates

- [ ] Pull request targets a protected branch and is not pushed directly to `main`.
- [ ] CI must pass before merge.
- [ ] Branch must be up to date before merge.
- [ ] At least one review is required before merge.
- [ ] Security review is required for `.github/`, `docs/security/`, `backend/security_layer/`, `backend/onyx/security_layer/`, sandbox, MCP, retrieval, tool, approval, audit, and policy files.

## How Has This Been Tested?

<!-- Describe the exact tests/checks run, including commands and results. -->

## Additional Options

- [ ] [Optional] Please cherry-pick this PR to the latest release version.
- [ ] [Optional] Override Linear Check
