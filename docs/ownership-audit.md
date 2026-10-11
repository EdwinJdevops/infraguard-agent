# Ownership audit and provider verification — 2026-10-11

## Scope and starting point

This upgrade builds on PR #5 head `c90cf2a4968bc086a49f52976bce6b04556f41ec`.
It corrects the existing SSH-remediation capability; it does not add a publisher, queue worker,
cloud credentials, or infrastructure mutation. PR #2 and #5 remain separate review boundaries.

The starting branch passed 82 tests. Passing those tests did not establish correct Terraform
ownership. Before changing implementation, 23 new regression cases failed against that head.
The exact test names and inputs are retained in `tests/test_terraform_ownership.py`.

## Reproduced defects

| Input | Previous result | Correction and consequence |
|---|---|---|
| Source SG ID changed while state still names the observed SG | Classified as standalone owner | Require literal source SG ID to equal the finding and state; unresolved references are manual |
| `provider = aws.other` | Classified as standalone owner | Reject target provider overrides and state provider aliases |
| `lifecycle.ignore_changes = [cidr_blocks]` | Classified as standalone owner despite edit potentially having no effect | Reject all target lifecycle blocks until their semantics are evaluated by a runtime plan gate |
| `create_before_destroy` or provisioner on target | Classified as standalone owner | Reject target lifecycle, provisioner, and connection blocks |
| State has a single indexed, deposed, or tainted instance | Metadata discarded; classified as the unindexed owner | Preserve eligibility consequences of instance metadata; reject the entire resource if any instance is unsupported |
| Legacy target combines another CIDR family, SG source, or `self` | Selected source matched; extra sources ignored | Require exactly one source across source and state; also cover prefix lists |
| Root includes JSON configuration or an override file | File ignored or parsed without Terraform merge semantics | Reject the root; never edit an apparent base declaration without evaluating all effective configuration |
| Null resources/instances, invalid attributes, wrong state version, boolean serial | Uncaught `AttributeError` or silently accepted input | Domain errors and explicit version-4/type checks |
| Duplicate JSON keys | Later key silently wins | Reject duplicate keys before evaluating state |

Additional tests cover both resource forms, conflicting state sources, duplicated managed
addresses, state provider aliases, and incomplete planner references. The planner no longer treats
a standalone ownership label alone as adequate evidence. Matching proof kind, rule ID, lineage,
integer serial, and file path are required. These fields remain forgeable internal data; this is
consistency validation, not authenticated state acquisition.

The legacy fixture previously used the AWS `sgr-` rule ID as the Terraform resource `id`.
The provider uses a synthetic `sgrule-` ID for that resource and exposes the AWS ID separately as
`security_group_rule_id`. The fixture now reflects that distinction.

## Terraform semantics that change the safety assessment

Terraform consumes both `.tf` and `.tf.json`, and merges override files after normal configuration.
Ignoring these files can produce a patch to a declaration that does not control the effective
configuration. Reference: [HashiCorp override semantics](https://developer.hashicorp.com/terraform/language/files/override).

The pinned AWS provider's legacy rule schema declares both CIDR attributes `ForceNew`.
Changing the CIDR therefore plans deletion and creation of the Terraform resource. It must not be
described as an in-place cloud update. The newer ingress resource's CIDR schema does not require
replacement. Provider sources reviewed:

- [Legacy schema at v6.10.0](https://github.com/hashicorp/terraform-provider-aws/blob/v6.10.0/internal/service/ec2/vpc_security_group_rule.go)
- [Ingress schema at v6.10.0](https://github.com/hashicorp/terraform-provider-aws/blob/v6.10.0/internal/service/ec2/vpc_security_group_ingress_rule.go)

Replacement may interrupt access. Plan actions alone cannot establish interruption duration,
reachability, or successful deployment. A future runtime policy must distinguish an approved
single-rule source update from replacement requiring explicit disruption review. Do not write a
universal “no replacements” requirement while also claiming legacy CIDR replacement is supported.

## Reproducible provider test

`tests/integration/test_terraform_provider_plans.py` performs:

1. Verify Terraform version 1.9.8 and initialize pinned AWS provider 6.10.0 with the committed lock
   file in read-only mode and no backend initialization.
2. Query the actual provider schema and encode synthetic state against its schema version.
3. Validate each trusted fixture and assert its baseline plan has no resource changes.
4. Generate the patch through InfraGuard's existing runbook and validate the patched configuration.
5. Plan with `-refresh=false`; assert exactly one intended resource changes, the approved source
   appears, and SG ID/ports remain unchanged.
6. Assert legacy delete/create versus newer ingress update; print tool versions, action lists,
   replacement paths, and a plan-JSON SHA256 in CI logs.

Credentials are literal test-only strings. EC2 and STS endpoints point to loopback, metadata is
disabled, and inherited AWS credentials/config are excluded from the subprocess environment.
There is no apply command. Raw state and plan files stay in temporary test directories; only
bounded summaries are logged. The plan hash identifies that run, not a portable golden snapshot.

The unit suite skips these tests unless `INFRAGUARD_TERRAFORM_INTEGRATION=1`; the dedicated CI job
sets that flag and fails if Terraform is unavailable. A skipped test is not a successful provider
check. The versions are a reproducible test pair, not a claim of latest releases or general
compatibility with every Terraform/provider version.

## Evidence and limits

At implementation time, local Ruff, diff checks, Terraform formatting, and 120 unit/component
tests passed. Four IPv4/IPv6 provider integration cases are skipped in the normal local suite.
The official Terraform Linux archive SHA256 was verified and `terraform init` authenticated the
provider signature and generated its checksum lock. Local provider execution failed because this
workspace denies the Unix socket used by Terraform's plugin protocol.

GitHub Actions [run 38144646302](https://github.com/EdwinJdevops/infraguard-agent/actions/runs/38144646302)
subsequently passed all four jobs on implementation head
`58e3cc3ae63bd4afc4143db343e483b2d42f2307`: Python lint/120 unit tests, Terraform formatting,
container build, and four real-provider IPv4/IPv6 plan cases. Both legacy-family plans required
delete/create and both newer ingress-family plans required update.
The first provider runs correctly rejected inaccurate synthetic baseline state; the harness was
corrected to include the provider's region and preserve absent optional tags as null. The baseline
no-op assertion was retained. No customer or live AWS state was used.
This run is an implementation checkpoint; the latest PR head must have its own passing checks.

This is fixture integration, not an operational remediation or a production safety gate.
It does not authenticate a customer backend, verify a workspace, refresh live state, run a
deployed worker, publish a remediation PR, deploy a patch, or prove effective exposure reduction.
The internal `auto_pr` result still represents local candidate eligibility only. A publisher must
not consume it until the following production controls are implemented and verified.

## Next engineering boundary

The next deliverable is an isolated analysis worker with a versioned evidence manifest binding:

| Input/output | Binding required |
|---|---|
| Repository | Allowlisted repository, exact commit SHA, source content hashes |
| State | Authorized backend/workspace, lineage/serial, acquisition time, content digest |
| Finding | Live rule fingerprint, verified account/region, bounded observation age |
| Toolchain | Terraform version, provider lock digest, provider versions |
| Plan | Commands/exit status, configuration/state input digests, raw-plan hash, policy result |
| Authorization | Deployment-owned CIDR policy version and explicit replacement/disruption policy |

The worker must have a constrained filesystem, process/time limits, restricted network access,
and read-only cloud permissions. Terraform configuration and providers execute code: running
customer configuration in the API process would be an unsafe architectural shortcut.

Production remains blocked on that worker and plan policy, authentic state acquisition, runtime
AWS composition, durable idempotency/audit, isolated GitHub publication, and independent
post-deployment verification. Human review and the protected-main merge requirements remain
unchanged. This upgrade is valuable because it removes demonstrated unsafe assumptions; it does
not close those remaining gates.
