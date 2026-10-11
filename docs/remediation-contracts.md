# Remediation contracts

This document defines the behavior callers and future publishers may rely on. It is deliberately
narrower than the product vision.

## Request contract

`POST /v1/remediation-plans` requires `X-API-Key` and a strict JSON body. Unknown fields are
rejected.

| Field | Constraint |
|---|---|
| `alert_id` | 1-128 characters; alphanumeric first character; then alphanumeric, `.`, `_`, `:`, or `-` |
| `provider` | `aws` |
| `account_id` | Exactly 12 digits; format only, not live identity proof |
| `region` | AWS commercial/GovCloud-style region format; format only |
| `resource_type` | `aws_security_group` |
| `resource_id` | AWS security group ID shape |
| `rule.direction` | `ingress` |
| `rule.protocol` | `tcp` |
| `rule.from_port`, `to_port` | 0-65535; the range must contain port 22 to qualify |
| `rule.source` | `0.0.0.0/0` or `::/0` |
| `replacement_source` | Optional syntactically; required for automatic eligibility |

Authentication does not prove the finding came from AWS. The HTTP schema intentionally cannot
assert internal provenance, so direct requests cannot produce a patch and return `manual_review`.
Trusted findings must be created by the AWS verification core described in
[`trusted-finding-provenance.md`](trusted-finding-provenance.md).

## Decision contract

| Decision | Meaning | Patch/evidence |
|---|---|---|
| `auto_pr` | All implemented planning gates passed | Patch, passing validation, evidence, and PR body are returned |
| `manual_review` | Finding may be real, but ownership or supported editability is not proven | No patch or publication evidence |
| `reject` | Finding or replacement violates the supported capability/policy | No patch or publication evidence |

For the HTTP endpoint, an otherwise valid public-SSH claim stops at `manual_review` before reading
Terraform because it has no independent AWS provenance. The `auto_pr` contract applies to internal
callers that supply a provenance-bound finding; no such runtime worker is currently shipped.

`can_open_pr` is stricter than the decision field: it is true only when an `auto_pr` decision also
has a patch, passing validation, JSON evidence, and PR Markdown. It is a local-stage result.
A future publisher also needs bound plan evidence, authenticated input acquisition, authorization,
freshness and base-SHA rechecks, and its own recorded publication result.

## Ownership contract

| Ownership | Proof | Behavior |
|---|---|---|
| `terraform_standalone_rule` | One literal root-module resource with no `count`/`for_each`, provider override, lifecycle, provisioner, or connection; one unindexed, non-deposed, ready default AWS-provider state instance; exactly one source; matching source/state SG ID, semantics, and live rule ID | Eligible for local policy and patch gates; production publication gates remain open |
| `terraform_inline_rule` | One direct root-module parent security group and exactly one inline rule match, with parent ID proven by state | `manual_review`; no inline editor exists |
| `unmanaged_remote_rule` | Reserved for a future cloud-correlated path | `manual_review` |
| `unknown` | No supported unique Terraform owner | `manual_review` |

State must be raw version-4 JSON with nonempty lineage and an integer non-negative serial.
Duplicate keys, malformed resource/instance attributes, and duplicate managed addresses are
errors. Roots with `.tf.json`, `override.tf`, or `*_override.tf` are rejected because the scanner
does not implement Terraform's JSON or merge semantics. Source SG references and expressions
require plan resolution and are ineligible even if old state appears to match.

Any malformed `.tf` file in the scanned root or malformed supplied state fails the request. A
missing state path is an error. Missing state evidence, zero/multiple state instances, `count`/`for_each`,
or state/source mismatch produces no standalone owner and therefore `manual_review`. More than one
matching resource is an error. Nested module files are not scanned. Terraform source symlinks and
files resolving outside the configured root are rejected. This favors false negatives over unsafe
edits. The current local state contract records lineage and serial but does not authenticate state
origin or prove freshness. Planner references must also carry matching rule ID, proof kind,
lineage, serial, and path; these fields are internal consistency checks, not authenticated evidence.
A production workflow must bind state to an immutable checkout and
workspace before enabling this gate.

## Replacement policy

The normalized CIDR must satisfy both conditions:

1. It is inside RFC1918 IPv4 (`10/8`, `172.16/12`, `192.168/16`) or IPv6 ULA (`fc00::/7`).
2. It exactly matches a normalized entry in deployment configuration
   `INFRAGUARD_ALLOWED_SSH_CIDRS`.

Private addressing alone does not prove reachability, least privilege, business approval, or a
working access path. The deployment owner is accountable for the allowlist.

## Patch contract

For an eligible standalone resource, InfraGuard changes exactly one static source attribute:

| Resource | IPv4 attribute | IPv6 attribute |
|---|---|---|
| `aws_security_group_rule` | `cidr_blocks` | `ipv6_cidr_blocks` |
| `aws_vpc_security_group_ingress_rule` | `cidr_ipv4` | `cidr_ipv6` |

The in-memory patch must:

- modify the uniquely identified resource;
- remove the relevant public source from that resource's source attribute;
- insert the approved replacement;
- preserve SSH ingress semantics;
- parse as HCL after the edit;
- produce exactly one removed and one added source line.

Unsupported formatting or expressions fail closed. Local semantic validation is necessary but not
sufficient for production publication; Terraform CLI validation and plan policy are still required.

The separate integration suite uses Terraform 1.9.8 and the real AWS provider 6.10.0 with a
committed checksum lock, synthetic state, disabled refresh, and loopback service endpoints.
It asserts a no-op baseline and a single planned resource change after patching. The legacy
`aws_security_group_rule` CIDR attributes are `ForceNew` in that provider: the expected plan is
delete/create, not an in-place edit. The newer ingress resource permits a source update.
Fixture checks do not authorize production replacement. A runtime plan gate must reject unrelated
changes and require an explicit disruption policy for replacements.

## Bound analysis contract

The internal functions in `infraguard/analysis.py` prepare a candidate from immutable source bytes
and evaluate an executor-supplied plan. They are not HTTP endpoints or an executor.
See [bound-analysis.md](bound-analysis.md) for the full input, result, and trust contracts.

| Result | Exact meaning |
|---|---|
| `update_candidate` | Pinned-format plan passes the narrow source-only update policy; human review and production gates remain |
| `replacement_review` | Only the approved legacy source change is represented, but delete/create requires disruption review; no automatic authorization |
| `reject` | Integrity, age, structure, semantics, scope, check, or toolchain gate failed |

The input manifest binds repository identity and commit assertion, original/patched source digests,
provider lock, raw state digest/lineage/serial/location assertion, finding, patch, operator policy,
tool versions, preparation and expiry. The result includes manifest/plan hashes, bounded reason,
actions, `publication: not_attempted`, and `state_origin_attested: false`.
Expected metadata must be independently supplied by a trusted coordinator, never accepted from an
HTTP claimant or calculated solely from that claimant's artifacts. That coordinator is not shipped.

## API operational contract

- `/livez` proves only that the process can answer HTTP.
- `/readyz` and `/health` validate required local configuration and return `503` when unusable.
- API documentation is disabled unless `INFRAGUARD_DOCS_ENABLED=true`.
- Untrusted-claim triage is limited to five requests per minute per observed client address, per
  process.
- Responses include a bounded request ID, `Cache-Control: no-store`, and
  `X-Content-Type-Options: nosniff`.
- The legacy `/remediate` endpoint returns `410 Gone` after authentication.
- Absolute Terraform paths are not returned by the API.
- `publication` is always `not_attempted` in this version.

The rate limiter is not distributed and proxy address trust must be configured at the deployment
edge. Do not run multiple replicas without a gateway/shared limiter and idempotency store.

## Compatibility

This is an alpha contract. Breaking changes require an API version change or an explicit migration
plan before a stable release. The current endpoint is versioned as `/v1`, but the repository has not
yet declared v1 generally available.
