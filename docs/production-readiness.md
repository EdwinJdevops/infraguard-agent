# Production readiness review

## Verdict

**The baseline is credible as an alpha engineering foundation, but it is not production-ready.**

The deterministic core corrects the fatal behavior in PR #1, narrows automatic scope, fails closed
on ambiguity, and produces test-backed evidence. The trusted-finding feature adds a strict
Security Hub CSPM parser, live EC2 rule binding, and internal provenance-consistency checks. It is
still only a library boundary: no AWS queue/worker/IAM composition or real-account integration
test exists, and the checksum is not a signature.
Required GitHub Actions jobs passed on PR #2 merge refs; this follow-on branch requires its own CI
evidence. The baseline can be merged as an alpha foundation only after branch protection and
independent human review. It must not be marketed or deployed as an autonomous production
remediator.

PR #1 added a restricted allow rule without removing the public allow rule. It was closed unmerged
as superseded by PR #2.

## Evidence at this checkpoint

| Area | Evidence | Assessment |
|---|---|---|
| Deterministic decision core | Explicit `auto_pr`, `manual_review`, and `reject` paths | Implemented |
| Ownership | Root-module static HCL plus required state/rule-ID correlation for local patch eligibility; ambiguity and parse failures stop automation | Implemented for documented subset; bound-analysis core adds age/input/plan checks but authenticated acquisition remains open |
| Patch | Targeted IPv4/IPv6 standalone rule source replacement | Implemented for documented subset |
| Validation | Before/after HCL and target semantics plus exact diff-shape check | Implemented, not Terraform-contextual |
| API | Strict schema, API-key check, readiness, request IDs, sanitized paths/errors, no publication | Implemented baseline |
| Tests | Ownership baseline: 120 unit/component tests and four opt-in real-provider cases. Bound analysis adds adversarial integrity/freshness/plan tests and evaluates actual provider JSON | Baseline CI run 38144902183 passed at 1723788; this follow-on requires its own green CI |
| Lint | Ruff over the repository | Passed locally; the current stacked-PR merge ref must also be green |
| Container | Non-root image definition and CI build job | PR merge-ref build passed in GitHub Actions; local Docker was unavailable |
| Kubernetes | Restricted pod settings and deny-egress policy | YAML parses; no local schema/cluster/CNI verification |
| External publishing | No GitHub publisher in runtime | Not implemented |
| Live cloud verification | Protocol-based STS identity and EC2 rule verification core | Implemented and fake-client tested; runtime composition and real AWS tests open |

Latest PR #2 baseline CI snapshot:
[run 34834010052](https://github.com/EdwinJdevops/infraguard-agent/actions/runs/34834010052).
For pull-request events, GitHub Actions checks the synthetic merge ref formed from the PR head and
current base. The latest required check suite attached to the reviewed head is the release
evidence; historical run links are snapshots, not substitutes for current checks.

## Release gates

| Priority | Gate | Exit evidence | Status |
|---|---|---|---|
| P0 | Close/supersede unsafe PR #1 | PR records why additive rules do not remediate exposure | Completed: closed unmerged in favor of PR #2 |
| P0 | Protected branch and mandatory CI | Ruleset requires tests, container build, review, resolved conversations, and blocks force push | Main protection verified on 2026-10-11; independent approval remains absent; new provider job is not yet a required ruleset context |
| P0 | Verified finding provenance | Security Hub event and read-only AWS lookup bind account, region, SG, rule, request IDs, and times | Core implemented and locally tested; runtime AWS/SQS/STS composition and real-account evidence open |
| P0 | Immutable repository input | Ephemeral clone of allowlisted repository at exact SHA; source digest recorded | Partial: Git-object capture and digest binding implemented; authorized acquisition/controller and immutable executor remain open |
| P0 | Contextual Terraform validation | Isolated `fmt`, `init -backend=false`, `validate`, and policy-checked plan JSON attached as evidence | Partial: internal pinned JSON policy and bound manifest implemented; sandbox executor and authenticated production state/plan evidence remain open |
| P0 | Legacy replacement semantics | Actual provider plan proves all source semantics and explicit disruption authorization | Blocked: pinned legacy replacement fixtures leave source_security_group_id unknown and the new gate rejects them; conditional review branch has only synthetic unit evidence |
| P0 | Safe publisher boundary | Dedicated GitHub App, short-lived installation token, base-SHA recheck, no force push, no direct main write | Open |
| P0 | Idempotency and concurrency | Durable key/lock prevents duplicate or conflicting PRs and records retries | Open |
| P0 | Post-deployment verification | Independent AWS check proves public rule removal and escalates regression | Open |
| P0 | Secrets/state handling | Threat-reviewed state acquisition, redaction tests, encryption, retention, access audit | Open |
| P1 | Durable workflow/audit store | Every transition, actor, input/output hash, policy/engine version, and failure is queryable and tamper-evident | Open |
| P1 | Production identity and authorization | TLS, workload/OIDC identity, tenant/repository authorization, rotation/revocation | Open |
| P1 | Distributed abuse controls | Shared rate limits, quotas, request-size/time limits, queue backpressure, dead-letter policy | Open |
| P1 | Supply-chain release | Digest-pinned base image, lock/hashes, dependency and image scan, SBOM, signature, provenance | Open |
| P1 | Integration resilience | Real Terraform CLI fixtures, modules/indexed resources policy, property/fuzz tests, GitHub API contract tests | Four pinned offline provider-plan cases passed in CI; broader resilience open |
| P1 | Observability and SLOs | Structured metrics/logs/traces, dashboards, alerts, SLO/error budget, runbooks exercised | Open |
| P1 | Recovery | Backup/restore and workflow replay tested; publisher rollback/PR closure procedure exercised | Open |
| P2 | Preferred no-SSH remediation | Detect Session Manager readiness and propose removal of SSH ingress where policy permits | Research/design |
| P2 | Broader findings/providers | Each new remediation has its own ownership, policy, patch, plan, and verification contract | Deferred |

SLSA provides a useful maturity model for build provenance and tamper resistance, but claiming a
level requires evidence, not a workflow label: [SLSA levels](https://slsa.dev/spec/v1.1/levels).

## Sequenced delivery plan

### Phase 0 — merge the honest baseline

1. Keep PR #2 draft until a `main` ruleset requires the named CI jobs, one independent approval,
   resolved conversations, and blocks force pushes/deletion.
2. Obtain independent code/security review against the current PR #2 head and merge-ref checks.
3. Merge only after those controls are evidenced. Tag it as an alpha baseline, not a production
   release.

PR #1 is already closed unmerged as unsafe and superseded; PR #2 is published and its latest
baseline merge-ref CI is green. Governance remains the blocking Phase 0 work.

Engineering may continue on isolated draft branches while review is pending; this does not
authorize merging or a production release. The 2026-10-11 [ownership audit](ownership-audit.md)
records demonstrated defects, supported-scope corrections, and the next worker boundary.

### Phase 1 — trustworthy inputs and immutable analysis

1. Deploy the accepted EC2.13 ASFF contract behind EventBridge, encrypted SQS/DLQ, allowlisted role
   mapping, mandatory freshness policy, and bounded AWS retries.
2. Add tenant/repository policy mapping; callers cannot choose arbitrary repositories or allowlists.
3. Create a durable workflow record and idempotency key.
4. Run each analysis in an ephemeral workspace cloned at a recorded SHA.
5. Acquire state through a trusted backend workflow; never accept an arbitrary caller path.

### Phase 2 — Terraform-native safety gate

1. Pin Terraform and provider versions and verify lock files.
2. Format and initialize without backend access where possible.
3. Run validate and a read-only plan in a sandbox with CPU, memory, time, and network limits.
4. Evaluate plan JSON: exactly one intended rule source changes, no privilege expansion or unrelated
   diff. The legacy provider forces deletion/creation on CIDR changes; replacements require explicit
   disruption policy and review, and must never be silently treated as an in-place update.
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
