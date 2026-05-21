# Security Layer Known Limitations

## Artifact scanner enforcement

Artifact scanning modules and tests are present, but a repository-wide mandatory enforcement hook for every artifact export/download/generation path is not currently wired. Artifact scanning should be treated as module-ready, not globally enforced runtime policy.

## Sandbox guard enforcement

Sandbox guard components are present, but global runtime pre-execution enforcement across all code-execution launch paths is not fully integrated. Sandbox guard should be treated as readiness functionality, not global runtime enforcement.
