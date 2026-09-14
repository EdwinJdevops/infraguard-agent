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

Authentication does not prove the finding came from AWS. Finding provenance is a production
release gate.

## Decision contract

| Decision | Meaning | Patch/evidence |
|---|---|---|
| `auto_pr` | All implemented planning gates passed | Patch, passing validation, evidence, and PR body are returned |
| `manual_review` | Finding may be real, but ownership or supported editability is not proven | No patch or publication evidence |
| `reject` | Finding or replacement violates the supported capability/policy | No patch or publication evidence |

`can_open_pr` is stricter than the decision field: it is true only when an `auto_pr` decision also
has a patch, passing validation, JSON evidence, and PR Markdown. A future publisher must require
`can_open_pr`, rerun freshness checks, and then record its own publication result.

## Ownership contract

| Ownership | Proof | Behavior |
|---|---|---|
| `terraform_standalone_rule` | One supported standalone resource matches rule attributes and security-group identity | Eligible for policy and patch gates |
| `terraform_inline_rule` | One parent security group and inline rule match, with parent ID proven by state | `manual_review`; no inline editor exists |
| `unmanaged_remote_rule` | Reserved for a future cloud-correlated path | `manual_review` |
| `unknown` | No supported unique Terraform owner | `manual_review` |

Any malformed `.tf` file in the scanned root or malformed supplied state fails the request. More
than one matching resource is an error. Terraform source symlinks and files resolving outside the
configured root are rejected. This favors false negatives over unsafe edits.

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

## API operational contract

- `/livez` proves only that the process can answer HTTP.
- `/readyz` and `/health` validate required local configuration and return `503` when unusable.
- API documentation is disabled unless `INFRAGUARD_DOCS_ENABLED=true`.
- Planning is limited to five requests per minute per observed client address, per process.
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
