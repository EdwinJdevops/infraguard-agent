# Bound analysis: implementation and remaining trust boundary

This change upgrades the existing public-SSH remediation core. It does not add another finding
type or an autonomous publisher. It closes a specific gap: a locally valid patch previously had
no contract connecting returned Terraform plan evidence to the inputs used to generate it.

## Implemented interfaces

1. `capture_repository_snapshot` reads Git blobs at the supplied 40-character commit SHA.
   It ignores changed and untracked working-tree files. It captures direct Terraform configuration,
   automatic variable files, and the dependency lock in one selected root. Symlink/executable Git
   modes, noncanonical roots, duplicate/unsafe filenames, and oversized inventories are rejected.
2. `prepare_public_ssh_analysis` checks independently supplied expectations, input age, lock
   contents, and the existing ownership/policy/patch/local validation gates. It materializes source
   in its own temporary directory, keeps state outside that root with mode 0600, then removes the
   temporary files. This is filesystem hygiene, not an execution sandbox.
3. `evaluate_bound_plan` rechecks prepared artifacts, envelope/toolchain/plan timestamps and expiry,
   then evaluates the narrow plan policy. It never invokes Terraform, GitHub, or AWS.

These interfaces are internal library functions. The API remains untrusted-claim triage and
cannot supply provenance or expectations. No coordinator or production executor is implemented.

## Input and output contracts

| Input | Required binding | What remains unproven |
|---|---|---|
| Repository snapshot | Repository name, commit, root, original and patched source inventories | Authorized repository origin/acquisition; other roots/modules are unsupported |
| Dependency lock | Expected byte digest, only AWS provider 6.10.0, nonempty checksum entries | Parsing checksum entries does not verify a binary; executor must use readonly init and approved installed binaries |
| State snapshot | Expected bytes/digest, lineage, integer serial, backend/workspace assertion, collection time | Authentication of backend/workspace, current generation, and collection actor |
| Finding | Existing provenance checks, full finding digest, live-rule fingerprint, verification time | Runtime verifier identity and attestation |
| Operator policy | Allowlist, policy revision and digest; selected source must pass existing policy | Operator authorization, reachability, access continuity |
| Plan | Manifest ID, plan hash, pinned format/toolchain, timestamp, result at or before expiry | A hash cannot prove which executor produced the plan or that it used those inputs |

The manifest schema is `analysis-input-v1`; results use `analysis-result-v1`, policy
`public-ssh-plan-v1`. Source inventories hash a sorted JSON list of filename/content-digest
pairs. The manifest includes the original/patched inventory digests, full patch/finding digests,
raw state and lock digests, lineage/serial, hashed backend/workspace assertion, verification and
collection times, approved source, policy revision/allowlist digest, tool versions, preparation and
expiry. Identical logical inputs prepared at different times can have different manifest IDs.

Freshness defaults to 300 seconds and accepts an explicit internal policy of 1–900 seconds.
State collection and finding verification must not be in the future. Expiry is the earlier input
time plus that age limit, checked again on plan completion. Terraform's second-resolution plan
timestamp may equal the preparation second; a timestamp from an earlier second is rejected.
The system clock and all timestamps must come from a trusted coordinator/executor.

The public result exposes only manifest and plan hashes, policy version, disposition, bounded
reason/actions, `publication: not_attempted`, and `state_origin_attested: false`. Raw state,
raw plan, source, internal paths, backend names, and AWS identities are absent. The prepared object
and manifest are confidential internal artifacts; do not return or log them. JSON rejects duplicate
keys, nonfinite/overflow numbers, nesting deeper than 64, non-object roots, and oversized payloads.
Limits are 16 MiB state, 32 MiB plan, 64 direct source files, 2 MiB per file and 8 MiB inventory.
These are parser limits, not a complete CPU/memory isolation policy.

## Plan policy

Compatibility is deliberately pinned to Terraform 1.9.8, plan JSON format 1.2 and AWS provider
6.10.0. An upgrade requires new provider evidence and a policy review; this is not general
Terraform compatibility.

The plan must be complete, applyable, and not errored, with no recorded drift or deferred changes.
Exactly the intended root managed resource may change. Other listed resources must be genuine
known no-ops; no moves, deposed entries, imports, generated configuration or changed outputs.
Prior/planned values must agree with the change summary and include the same resource addresses.
Child modules are unsupported. The configured target must use the default AWS provider and static
approved source/group expressions, with no count or for_each.

The target's before attributes must match supplied state and verified group/rule/ports/protocol.
The approved source is the only semantic attribute permitted to differ. JSON comparison preserves
boolean/number distinctions. Absent optional attributes and explicit null are equivalent during
provider state decoding; strings, booleans, lists and empty collections are not coerced.

| Resource | Accepted actions | Result |
|---|---|---|
| `aws_vpc_security_group_ingress_rule` | `update`, no unknown rule values or replacement trigger | `update_candidate` |
| `aws_security_group_rule` | `delete, create`, exactly the source replacement path, only replacement IDs unknown | `replacement_review` |
| Either | Unrelated changes, altered semantics, unsupported structure, unknown checks or inconsistency | `reject` |

An update candidate still needs human review and production release gates. Replacement review is
an escalation requiring an operator to assess loss of access and the replacement interval.
No result is an automatic disruption authorization or proof that public access is removed in AWS.

**Real-provider limitation:** AWS provider 6.10.0 marks `source_security_group_id`
optional/computed. Both actual legacy CIDR replacement fixtures leave it unknown, so the gate
rejects them as `unknown_rule_semantics`. Diagnostics also show differences in description, unused
CIDR-family and prefix-list attributes; their normalization semantics have not been accepted.
The conditional replacement-review branch is tested with synthetic fully known source semantics;
there is no accepted real-provider legacy replacement evidence at this checkpoint. Do not relax
unknown-source checks or describe that branch as production support. Resolving this needs a separate
provider-semantic/disruption policy review, with adversarial and actual-provider evidence.

## Verification evidence and limits

Unit tests attack metadata mismatches, old/future evidence, prepared artifact changes, stale plan
completion, envelope mismatch, unexpected actions, hidden/unrelated changes, altered values,
unknown semantics, outputs/checks, modules/aliases/imports, Git symlinks and malformed JSON.
The opt-in integration suite captures synthetic source in real Git commits, produces real
Terraform/provider plans, passes their JSON through this gate and rejects a mutated port.
It covers both standalone resource types and IPv4/IPv6, with a strict no-op baseline.
Both newer ingress plans must yield update candidates; both legacy plans must exhibit the specific
unknown source-group field and be rejected. Provider action assertions still independently prove
the legacy delete/create and newer update behavior. Changing an expected disposition here records
an observed fail-closed compatibility limit; it does not authorize a previously rejected plan.

CI uses the committed checksum lock and test-only credentials with loopback AWS endpoints,
`-refresh=false`, and no apply. This establishes the pinned fixture behavior only. It does not
establish production IAM, remote state access, live AWS remediation, Docker isolation, a publisher,
or post-deployment verification. Latest green checks on the reviewed head are required; historical
baseline CI is not evidence that this new implementation passed.

## Next production composition

The next slice must supply a trusted acquisition/controller and isolated executor, with executable
tests for each boundary:

1. Authorize tenant/repository/root/backend/workspace independently of the submitted finding;
   acquire the exact commit and an authenticated state generation through read-only identities.
2. Verify a fresh live rule through the existing AWS verifier. Record acquisition actor, backend
   generation, code/policy versions and signed or integrity-protected manifest in a durable store.
3. Execute only pinned Terraform/provider binaries in a disposable restricted environment.
   No publisher/cloud credentials, host Docker socket, privileged mode, general host mounts or
   unrestricted network. Bound CPU, memory, process count, disk, time and captured output.
   Control provider installation and all variable/environment/CLI inputs; verify materialized hashes.
   Config and provider code are executable, even during validation/planning.
4. Supply a trusted plan envelope and apply the existing gate. Store encrypted confidential
   artifacts with retention/access audit; emit bounded sanitized evidence separately.
5. Make publication a separate authorized transition with repository/base SHA, freshness and policy
   rechecks, durable lock and explicit human review. Legacy replacement additionally needs explicit
   disruption approval. No apply permission belongs to the analysis worker.

The manifest ID identifies a particular attempt; it is not a durable deduplication lock. Define
the workflow key separately from tenant/repository/root/workspace/rule/base generation and policy,
with conflict handling and conditional transitions. On expired or failed analysis, discard the
candidate and acquire fresh inputs; do not reuse an old plan or automatically restore public SSH.
After deployment through the owner's existing pipeline, independently re-read AWS to prove the
public rule was removed and detect regressions. These recovery, idempotency, publication and
post-deployment transitions remain unimplemented release blockers.

## Primary references

- [Terraform JSON format](https://developer.hashicorp.com/terraform/internals/json-format):
  change actions, unknown values, replacement paths and values representations.
- [Terraform show](https://developer.hashicorp.com/terraform/cli/commands/show):
  JSON can expose sensitive values in plaintext.
- [Terraform 1.9.8 JSON plan implementation](https://github.com/hashicorp/terraform/blob/v1.9.8/internal/command/jsonplan/plan.go):
  the pinned format version and plan completion/error/timestamp fields.
- [AWS provider 6.10.0 legacy rule implementation](https://github.com/hashicorp/terraform-provider-aws/blob/v6.10.0/internal/service/ec2/vpc_security_group_rule.go):
  the optional/computed source-group field, source conflicts and replacement attributes.
