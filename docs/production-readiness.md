# Production readiness review

## Verdict

**The baseline is credible as an alpha engineering foundation, but it is not production-ready.**

The deterministic core corrects the fatal behavior in PR #1, narrows automatic scope, fails closed
on ambiguity, and produces test-backed evidence. It can be merged as a replacement foundation if
CI passes and review confirms the diff. It must not be marketed or deployed as an autonomous
production remediator.

PR #1 is a merge blocker in its current form because it adds a restricted allow rule without
removing the public allow rule. Close it as superseded; do not merge or stack production work on it.

## Evidence at this checkpoint

| Area | Evidence | Assessment |
|---|---|---|
| Deterministic decision core | Explicit `auto_pr`, `manual_review`, and `reject` paths | Implemented |
| Ownership | Static HCL plus optional state correlation; ambiguity and parse failures stop automation | Implemented for documented subset |
| Patch | Targeted IPv4/IPv6 standalone rule source replacement | Implemented for documented subset |
| Validation | Before/after HCL and target semantics plus exact diff-shape check | Implemented, not Terraform-contextual |
| API | Strict schema, API-key check, readiness, request IDs, sanitized paths/errors, no publication | Implemented baseline |
| Tests | 46 local tests, including read-only API and IPv6/state/path hardening | Passing locally at this checkpoint |
| Lint | Ruff over `api`, `infraguard`, and `tests` | Passing locally at this checkpoint |
| Container | Non-root image definition and CI build job | Local Docker build not verified in this environment |
| Kubernetes | Restricted pod settings and deny-egress policy | YAML parses; no local schema/cluster/CNI verification |
| External publishing | No GitHub publisher in runtime | Not implemented |
| Live cloud verification | No AWS integration in runtime | Not implemented |

Local results are not release evidence until the published branch runs in GitHub Actions.

## Release gates

| Priority | Gate | Exit evidence | Status |
|---|---|---|---|
| P0 | Close/supersede unsafe PR #1 | PR records why additive rules do not remediate exposure | Open until GitHub action completed |
| P0 | Protected branch and mandatory CI | Ruleset requires tests, container build, review, resolved conversations, and blocks force push | Open |
| P0 | Verified finding provenance | Signed provider event or read-only AWS lookup binds account, region, SG, rule, and observation time | Open |
| P0 | Immutable repository input | Ephemeral clone of allowlisted repository at exact SHA; source digest recorded | Open |
| P0 | Contextual Terraform validation | Isolated `fmt`, `init -backend=false`, `validate`, and policy-checked plan JSON attached as evidence | Open |
| P0 | Safe publisher boundary | Dedicated GitHub App, short-lived installation token, base-SHA recheck, no force push, no direct main write | Open |
| P0 | Idempotency and concurrency | Durable key/lock prevents duplicate or conflicting PRs and records retries | Open |
| P0 | Post-deployment verification | Independent AWS check proves public rule removal and escalates regression | Open |
| P0 | Secrets/state handling | Threat-reviewed state acquisition, redaction tests, encryption, retention, access audit | Open |
| P1 | Durable workflow/audit store | Every transition, actor, input/output hash, policy/engine version, and failure is queryable and tamper-evident | Open |
| P1 | Production identity and authorization | TLS, workload/OIDC identity, tenant/repository authorization, rotation/revocation | Open |
| P1 | Distributed abuse controls | Shared rate limits, quotas, request-size/time limits, queue backpressure, dead-letter policy | Open |
| P1 | Supply-chain release | Digest-pinned base image, lock/hashes, dependency and image scan, SBOM, signature, provenance | Open |
| P1 | Integration resilience | Real Terraform CLI fixtures, modules/indexed resources policy, property/fuzz tests, GitHub API contract tests | Open |
| P1 | Observability and SLOs | Structured metrics/logs/traces, dashboards, alerts, SLO/error budget, runbooks exercised | Open |
| P1 | Recovery | Backup/restore and workflow replay tested; publisher rollback/PR closure procedure exercised | Open |
| P2 | Preferred no-SSH remediation | Detect Session Manager readiness and propose removal of SSH ingress where policy permits | Research/design |
| P2 | Broader findings/providers | Each new remediation has its own ownership, policy, patch, plan, and verification contract | Deferred |

SLSA provides a useful maturity model for build provenance and tamper resistance, but claiming a
level requires evidence, not a workflow label: [SLSA levels](https://slsa.dev/spec/v1.1/levels).

## Sequenced delivery plan

### Phase 0 — merge the honest baseline

1. Publish this branch and run CI.
2. Review code and security contracts; fix every failed check.
3. Close PR #1 as unsafe and superseded.
4. Merge only after required human review. Tag it as an alpha baseline, not a production release.

### Phase 1 — trustworthy inputs and immutable analysis

1. Define a versioned finding envelope with detector, event ID, observed time, account, region,
   resource/rule identity, and signature/verification metadata.
2. Add tenant/repository policy mapping; callers cannot choose arbitrary repositories or allowlists.
3. Create a durable workflow record and idempotency key.
4. Run each analysis in an ephemeral workspace cloned at a recorded SHA.
5. Acquire state through a trusted backend workflow; never accept an arbitrary caller path.

### Phase 2 — Terraform-native safety gate

1. Pin Terraform and provider versions and verify lock files.
2. Format and initialize without backend access where possible.
3. Run validate and a read-only plan in a sandbox with CPU, memory, time, and network limits.
4. Evaluate plan JSON: exactly one intended rule source changes, no replacement resource churn,
   deletion, privilege expansion, or unrelated diff.
5. Persist commands, versions, exit status, plan hash, and policy result.

### Phase 3 — isolated GitHub publication

1. Build a GitHub App with repository allowlisting and minimum contents/PR permissions.
2. Mint installation tokens only inside a short-lived publisher worker.
3. Recheck base SHA, finding age, file digest, policy version, and plan evidence.
4. Create deterministic branch/PR identities; update an existing open remediation instead of
   duplicating it.
5. Enforce required checks and human approval through repository rulesets.

### Phase 4 — verification and operations

1. Consume merge/deployment events from the existing IaC delivery system.
2. Independently verify the effective AWS security group rule.
3. Close the workflow only after cloud evidence passes; otherwise page/escalate with a bounded
   retry policy.
4. Establish SLOs, security response ownership, on-call runbooks, audit retention, and recovery
   tests.

### Phase 5 — differentiated product

Prioritize high-confidence, provider-verified remediations rather than a generic “AI fixes cloud”
catalog. Strong candidates are:

- eliminate inbound SSH through Session Manager readiness and migration analysis;
- organization-aware exposure graphs that connect finding, Terraform owner, repository, service,
  owner, and deployment history;
- remediation simulation using plan JSON and policy-as-code;
- exception lifecycle management with owner, justification, expiry, and compensating controls;
- regression detection that links reintroduced exposure to the exact commit and policy decision;
- measured outcomes: time-to-triage, time-to-safe-PR, acceptance rate, false-positive rate, rollback
  rate, and verified exposure-reduction time.

These become defensible only when backed by real integrations and measured reliability. Adding an
LLM chat layer before the trust and verification system would not make InfraGuard production-grade.
