# Engineering instructions

## Product boundary

InfraGuard is currently a read-only Terraform remediation planner. Preserve these invariants:

- Never add direct AWS mutation or `terraform apply`.
- Never publish GitHub changes from `api/` or give the API process repository credentials.
- Never treat `decision == auto_pr` as proof that a PR exists; require `run.can_open_pr` and a
  separate publisher outcome.
- Never use LLM output for ownership, authorization, policy, patch generation, or validation.
- Never reintroduce the historical model-driven publisher into the production runtime.
- Fail closed on malformed HCL/state, ambiguous ownership, unsupported expressions, invalid
  replacement policy, or failed validation.
- Do not put real Terraform state, credentials, account data, or customer source in tests.
- Preserve API path sanitization and never return absolute workspace paths.

## Required change discipline

For every remediation capability, add and document all of:

1. versioned finding contract;
2. exact ownership proof;
3. policy decision and operator-controlled inputs;
4. narrowly targeted patch;
5. negative and adversarial tests;
6. Terraform-context validation plan;
7. human review evidence;
8. post-deployment cloud verification contract;
9. idempotency identity and rollback behavior.

No capability is production-eligible if one of these is unspecified.

## Verification

Run before every commit:

```bash
python -m ruff check api infraguard tests
python -m pytest -q
git diff --check
```

When available, also build the container and validate Kubernetes manifests. Do not claim those
checks passed if the required local tooling or target cluster was unavailable.

## Documentation truthfulness

Update `README.md`, `SECURITY.md`, `docs/remediation-contracts.md`, and
`docs/production-readiness.md` when a trust boundary or capability changes. Distinguish implemented,
locally tested, CI-verified, deployed, and production-proven states.
