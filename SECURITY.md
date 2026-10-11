# Security policy and threat model

## Security posture

InfraGuard is an alpha planning service, not an autonomous production remediator. The library has
a strict Security Hub CSPM parser and read-only AWS rule-verification boundary, but the current
runtime does not connect it to AWS. The API can only triage untrusted claims. It has no GitHub
client, cloud credentials, Terraform CLI execution, or apply path.

No claim in this repository should imply that credentials, identity federation, signed artifacts,
or post-deployment verification exist before the corresponding code and deployment evidence exist.

## Reporting a vulnerability

Do not put exploit details, credentials, Terraform state, or customer identifiers in a public
issue. Use GitHub's private vulnerability reporting for this repository if it is enabled. If it is
not available, open a minimal public issue asking the maintainer for a private reporting channel,
without disclosing the vulnerability.

No response-time SLA is currently offered. Establishing a staffed security contact and SLA is a
production release gate.

## Supported versions

Only the latest commit on `main` is maintained. There is no stable release or security backport
policy yet.

## Assets and trust boundaries

| Asset | Sensitivity | Current boundary |
|---|---|---|
| Terraform source | Integrity-critical; may reveal architecture | Operator-provided read-only checkout |
| Terraform state | Confidential; may contain secrets | Optional local read-only file; never returned by design |
| API key | Secret | Process environment or Kubernetes Secret |
| Finding payload | Integrity-critical; contains account/resource IDs | Direct API claims are unverified and cannot produce patches; verified internal objects require live AWS evidence |
| Generated diff/evidence | Integrity and confidentiality sensitive | Returned to authenticated caller; no durable store |
| Replacement allowlist | Security policy | Deployment configuration, not caller-controlled |

## Threat model

| Threat | Current mitigation | Residual risk / required production control |
|---|---|---|
| Spoofed or stale finding | Direct API claims stop before Terraform scanning; verifier core checks ASFF identity/freshness and current EC2 state | Runtime EventBridge/SQS/STS integration, authentic queue policy, durable replay defense, and real AWS integration tests are absent. |
| Confused-deputy role use | Verifier requires STS caller account to equal the finding target; event account is separately allowlisted | Runtime role mapping/external-ID policy is not implemented. Never accept a role ARN from event data. |
| Tampered source checkout | Deployment contract mounts source read-only; source symlinks and root escapes fail closed | The checkout's repository and commit are not authenticated. Use an ephemeral clone from an allowlisted repository and pin the exact base commit SHA. |
| Tampered or stale state | State is read-only; malformed JSON fails closed | State authenticity, lineage, serial, and freshness are not verified. Obtain state through a trusted backend workflow and bind it to the checkout/workspace. |
| Ambiguous ownership | Requires one literal root-module rule, matching SG/rule IDs and semantics, a default-provider unindexed ready state instance, and exactly one source; lifecycle, provisioners, aliases, JSON/override files, malformed/duplicate state fail closed | Modules, references, expression evaluation, and plan-derived ownership are unsupported. State origin and checkout/workspace binding remain unproven. |
| Patch targets wrong text | Patch is scoped to one resource and one CIDR attribute; semantic validation checks the target | Regex source editing supports only static forms. Move to an AST/token-preserving editor or Terraform-native transformation before expanding syntax coverage. |
| HCL parses but plan is unsafe | HCL/diff validation plus an internal bound JSON-plan policy rejects unrelated changes, unresolved rule semantics, moves/imports, inconsistent values, and incomplete/error plans; CI exercises synthetic provider plans | No isolated runtime executor exists. The legacy delete/create result requires disruption review. Hashes do not authenticate an executor or a plan. |
| Inputs swapped or stale during analysis | Git-object source capture and an internal manifest bind source/state/lock/finding/patch/policy; completion checks rehash prepared artifacts and enforce expiry | Backend/workspace/repository expectations and collection times are trusted coordinator assertions. No authenticated acquisition, attestation, durable evidence store, or publication recheck is shipped. |
| TOCTOU between analysis and publication | No publisher exists, so current service cannot publish stale output | Future publisher must compare repository/base SHA, file digest, finding freshness, and policy version immediately before commit and PR creation. |
| Duplicate/concurrent findings | None beyond per-process request rate limiting | Require an idempotency key derived from tenant/repository/finding/rule/base SHA and a durable lock/state machine. |
| Publisher token theft or overreach | No publisher credential exists in the runtime | Use a dedicated GitHub App installation token, scoped to selected repositories and minimum permissions, in an isolated short-lived publisher. GitHub states installation tokens expire after one hour and can be permission/repository scoped: [installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app). |
| Prompt injection / model-generated mutation | No LLM is used in the production planning path | Keep models out of authorization, ownership, policy, patch generation, and validation. Model output may explain evidence but must be treated as untrusted text. |
| State or path disclosure | API converts file paths to paths relative to the configured root and sanitizes evidence errors | Internal logs can contain parser details; logging policy, redaction tests, retention, and tenant isolation are not complete. |
| API credential guessing/replay | 32-character minimum, constant-time comparison, per-process rate limit | Static shared API keys are insufficient for multi-tenant production. Terminate TLS and use workload identity/OIDC, audience-scoped tokens, authorization, rotation, and gateway limits. |
| Network lateral movement | Kubernetes manifest denies egress and limits ingress; pod has no API token | NetworkPolicy enforcement depends on the cluster CNI and ingress namespace labels. Validate in the target cluster. |
| Container compromise | Non-root UID/GID 10001, read-only root filesystem, dropped capabilities, RuntimeDefault seccomp | Image is not yet published, digest-pinned, scanned, signed, or accompanied by provenance/SBOM. |
| Audit evidence tampering | Deterministic evidence is returned with each eligible plan | Evidence is not signed or durably retained. Store append-only records with input/output hashes, policy version, code version, actor, timestamps, and publication/verification transitions. |

## Current non-negotiable controls

- No direct AWS mutation and no `terraform apply`.
- No Terraform scan or patch from a finding lacking independent live-rule provenance.
- No PR publication from the API process.
- No patch unless Terraform ownership is exactly one supported resource.
- No caller-selected replacement outside the deployment-owned allowlist.
- No globally routable replacement source; only RFC1918 IPv4 and IPv6 ULA.
- No LLM output in any mutation or authorization decision.
- No Terraform state in responses, commits, logs, or test fixtures containing real data.
- Any parse ambiguity, malformed evidence, unsupported form, or failed validation stops automation.

## Deployment requirements

Use TLS at the ingress or API gateway. Keep one replica until rate limiting and idempotency use a
shared durable store. Use the supplied pod security settings and verify them against the Kubernetes
Restricted Pod Security Standard:
[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).
Protect `main` with required reviews and status checks; GitHub rulesets can require reviews, signed
commits, and block force pushes:
[About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets).

The complete release decision is maintained in
[`docs/production-readiness.md`](docs/production-readiness.md).
