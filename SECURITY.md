# Security Policy

## Supported Scope

GhostReconRev is designed for reconnaissance workflows.

- Scope enforcement.
- Evidence provenance.
- Input validation.
- Safe command execution.

## Reporting a Vulnerability

Please do not open public GitHub issues for security vulnerabilities.

Report privately with the following information.

- A clear description of the impact.
- Affected files and endpoints.
- Reproduction steps.
- Suggested mitigation, if available.

## Responsible Disclosure Expectations

- Give maintainers reasonable time to triage and patch.
- Avoid sharing exploit details publicly until a fix is available.
- Include version and commit information when reporting.

## Hardening Notes for Deployments

- Enable authentication in non-local environments. Set `APP_REQUIRE_AUTH=true`
and use a strong `APP_AUTH_USERNAME` and `APP_AUTH_PASSWORD`.
- Restrict host header allow-list (`ALLOWED_HOSTS`).
- Run behind TLS termination.
- Keep collector binaries pinned and sourced from trusted releases.
- Store artifacts and database on protected storage.
