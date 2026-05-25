# Step 2 Codespace Verification

Date: 2026-05-25
Branch: security-layer-mvp
Commit verified locally before evidence attempt: da52a8ebdb2825ae5cec743037bcb3ecc842d66d

## Git status

Local Codespace reported:

```text
On branch security-layer-mvp
Your branch is up to date with 'origin/security-layer-mvp'.
nothing to commit, working tree clean
```

## Recent commits verified locally

```text
da52a8e docs: record repository workflow protection evidence
153eaba ci: add repository workflow protection gates
d50c24c docs: add changelog for workflow controls
adab73e chore: add security workflow PR checklist
9be9275 chore: require security review ownership
```

## Step 2 file validation

PASS: Step 2 workflow files OK.

Validated files:

```text
.github/CODEOWNERS
.github/pull_request_template.md
.github/dependabot.yml
.github/workflows/repository-workflow-protection.yml
CHANGELOG.md
docs/security/repository_workflow_protection.md
```

## Secret-pattern scan

Result: FOUND expected test/demo placeholder secret strings.

Observed placeholder locations included test files, demo attack fixtures, security-layer policy examples, redaction tests, MCP tests, LLM provider tests, and UI placeholder text.

## GitHub Ruleset Manual Verification

Ruleset created manually in GitHub UI.

Ruleset name: Protect main workflow
Status: Active
Target branch: main

Enabled:

- Restrict deletions
- Require pull request before merging
- Required approvals: 1
- Require review from Code Owners
- Dismiss stale approvals
- Block force pushes

Temporarily not enabled:

- Require status checks to pass

Reason:

GitHub requires at least one discovered status check before this rule can be enabled. This will be enabled after the first PR workflow run exposes check names.

## Local push issue

The user created this evidence file locally and committed earlier evidence as:

```text
f3ca665 docs: add step 2 codespace verification evidence
```

The user later created a local manual-ruleset evidence commit as:

```text
c99ce2b docs: record manual main ruleset verification
```

Both local pushes failed with:

```text
remote: Permission to Amhdour/onyxBuildON.git denied to Amhdour.
fatal: unable to access 'https://github.com/Amhdour/onyxBuildON.git/': The requested URL returned error: 403
```

This remote file was therefore created and updated through the connected GitHub tool to preserve evidence on `security-layer-mvp`.

## Follow-up required

- Fix Codespace Git authentication or repository access before future local pushes.
- Update the CI secret-pattern scan allowlist/exclusions before making the scan a required status check.
- Enable `Require status checks to pass` after the first PR workflow run exposes check names.
- Record GitHub security settings availability for Dependabot alerts, Dependabot security updates, secret scanning, and push protection.
