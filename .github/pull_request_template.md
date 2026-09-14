## Scope

<!-- What changes, and what explicitly remains out of scope? -->

## Security and trust-boundary impact

<!-- Ownership, authorization, credentials, data, network, mutation, or verification changes. -->

## Evidence

- [ ] `python -m ruff check api infraguard tests`
- [ ] `python -m pytest -q`
- [ ] `git diff --check`
- [ ] Container build completed, or the limitation is stated below
- [ ] Terraform/Kubernetes checks relevant to this change completed, or limitations are stated

## Fail-closed and adversarial cases

<!-- List negative, malformed, ambiguous, stale, duplicate, and unsupported inputs tested. -->

## Known limitations / checks not run

<!-- Never claim a check that was not executed. -->

## Rollback and compatibility

<!-- How is this reversed, and does it change an API, policy, state, or evidence contract? -->

## Documentation

- [ ] Contracts and threat model updated, or no change is required with explanation
- [ ] No credentials, real Terraform state, customer data, or sensitive source included
