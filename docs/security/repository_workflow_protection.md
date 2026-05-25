# Repository Workflow Protection

Status date: 2026-05-25
Repository: `Amhdour/onyxBuildON`
Working branch: `security-layer-mvp`

## Purpose

This document records Step 2, "Protect repository workflow," for the Onyx Agent Runtime Security Layer effort.

## Controls implemented in repository files

| Control | Status | Evidence |
|---|---:|---|
| Protect `main` | Partial | Requires GitHub branch protection setting. Repository process now documents no direct pushes to `main`. |
| Require pull requests | Partial | PR checklist requires PR-based changes. GitHub branch protection must enforce this. |
| Require CI pass before merge | Partial | `.github/workflows/repository-workflow-protection.yml` defines required workflow checks. GitHub branch protection must mark these checks required. |
| Require review before merge | Partial | PR checklist requires review. GitHub branch protection must enforce required approving reviews. |
| Require security review for security-layer files | Implemented in repo files | `.github/CODEOWNERS` assigns security-sensitive paths to `@Amhdour`. GitHub branch protection must require CODEOWNERS review. |
| Block force-push to `main` | Manual GitHub setting required | Must be enabled in branch protection/rulesets. |
| Require branch up-to-date before merge | Partial | PR checklist requires branch freshness. GitHub branch protection must enforce up-to-date branches. |
| Enable secret scanning | Partial | CI includes common secret-pattern scan. GitHub secret scanning must also be enabled in repository security settings when available. |
| Enable dependency alerts | Partial | `.github/dependabot.yml` exists for GitHub Actions and backend pip updates. GitHub Dependabot alerts must be enabled in repository security settings. |
| Add `CHANGELOG.md` | Implemented | `CHANGELOG.md` created. |
| Use one control per PR | Implemented in process | `.github/pull_request_template.md` requires one control or one related control group per PR. |
| Use tests, docs, and evidence in same PR | Implemented in process | `.github/pull_request_template.md` requires tests, docs, evidence, and changelog updates. |

## Files added or changed

- `.github/CODEOWNERS`
- `.github/pull_request_template.md`
- `.github/workflows/repository-workflow-protection.yml`
- `CHANGELOG.md`
- `docs/security/repository_workflow_protection.md`

## Manual GitHub settings still required

The GitHub connector available in this environment can read and write repository files, commits, branches, issues, and PRs, but it does not expose branch protection/ruleset or repository security toggle mutations. Therefore the following must be enabled in GitHub UI or with a token/API that has branch-protection and security-events permissions:

1. Protect `main`.
2. Require pull request before merging.
3. Require at least one approving review.
4. Require review from Code Owners.
5. Require status checks to pass before merging.
6. Mark `Repository workflow protection / PR workflow policy` as required.
7. Mark `Repository workflow protection / Secret pattern scan` as required.
8. Mark `Repository workflow protection / Baseline Python compile check` as required.
9. Require branches to be up to date before merging.
10. Block force pushes to `main`.
11. Block deletions of `main`.
12. Enable Dependabot alerts.
13. Enable Dependabot security updates if available.
14. Enable secret scanning if available.
15. Enable push protection if available.

## Recommended GitHub UI path

1. Open repository settings.
2. Go to Rules > Rulesets, or Branches > Branch protection rules depending on GitHub UI availability.
3. Add or update protection for branch name pattern `main`.
4. Enable pull request requirement, required approvals, Code Owners review, required status checks, up-to-date branch requirement, and force-push blocking.
5. Go to Security > Code security and analysis.
6. Enable Dependabot alerts, Dependabot security updates, secret scanning, and push protection where available.

## Operating rule for future work

Future implementation work must use feature branches and PRs. Each PR should contain one control or one tightly related control group, with tests, docs, evidence, and changelog updates in the same PR.

## Limitations

This step does not prove that GitHub branch protection or GitHub Advanced Security toggles are active. It only adds repository-side workflow enforcement files and documents the manual settings required for full enforcement.
