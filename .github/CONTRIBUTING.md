# Contributing

InfraGuard changes infrastructure security policy. Narrow, reviewable, evidence-backed changes are
preferred over broad feature claims.

## Workflow

1. Branch from the latest `main` using `feat/`, `fix/`, `security/`, or `docs/`.
2. Keep commits focused and use conventional prefixes such as `feat:`, `fix:`, `security:`,
   `test:`, and `docs:`.
3. Add tests for positive, negative, ambiguous, malformed, and unsupported inputs.
4. Run the required verification commands from `AGENTS.md`.
5. Open a PR to `main` with scope, threat impact, test evidence, and known limitations.
6. Do not merge without required CI and human review.

There is no active `develop` branch contract. Do not create autonomous `fix/*` or
`infraguard/*` branches until the isolated publisher, idempotency, and repository rules are
implemented.

## Pull-request evidence

Every behavior change should state:

- what trust boundary or invariant changes;
- what can now be automated and what still fails closed;
- exact tests and tools run;
- any check not run and why;
- migration, rollback, and compatibility impact;
- whether documentation and threat model changed.

Never include credentials, real Terraform state, customer data, or sensitive source in issues,
fixtures, logs, or PR descriptions.
