# ADR 0002: live AWS verification before Terraform analysis

- Status: accepted
- Date: 2026-09-14

## Context

The planning API accepts caller-supplied finding metadata. Authentication identifies a caller but
does not prove that AWS emitted the finding or that the described exposure still exists. Security
Hub events are observations and can be delayed, replayed, malformed, or routed through a central
administrator account. Starting repository analysis from this metadata would let an untrusted
claim consume resources and potentially drive a future publisher.

Security Hub CSPM ASFF and Security Hub V2 OCSF events share the source `aws.securityhub` but use
different detail types and schemas. Conflating them would make parser behavior ambiguous.

## Decision

1. The first trusted intake is only Security Hub CSPM ASFF `Security Hub Findings - Imported` for
   consolidated control `EC2.13`.
2. The event account must be deployment-allowlisted, but the target account is taken from the
   internally consistent finding/resource identity and independently matched to STS caller identity.
3. A read-only EC2 lookup in the target region must prove exactly one current supported public SSH
   rule before Terraform ownership analysis starts.
4. Event and finding timestamps have mandatory age and future-skew limits.
5. AWS request IDs and a canonical rule fingerprint become part of finding provenance. The planner
   recomputes the fingerprint and refuses modified evidence.
6. Zero current matches is a resolved no-op. Multiple matches and all-protocol rules require human
   review. Invalid events are rejected. AWS/API evidence failures raise retryable operational errors.
7. Role selection is deployment policy, never event input. Runtime role assumption, queueing, and
   durable workflow state remain separate composition work.
8. Direct JSON requests without internally generated provenance can never produce a patch.

## Consequences

Positive:

- spoofed API fields cannot authorize an automatic Terraform edit;
- stale findings are checked against current AWS state;
- central Security Hub aggregation and target-account identity are not confused;
- provenance is bound to the exact normalized rule consumed by the planner;
- duplicates and unsupported broad rules stop automation.

Costs and limitations:

- the HTTP API is now triage-only until a trusted AWS worker is composed;
- strict ASFF and resource requirements create intentional false negatives;
- live verification adds AWS latency, throttling, IAM, retry, and regional failure modes;
- V2/OCSF, ISO partitions, other controls, and non-CIDR rule sources need separate contracts;
- this decision alone does not establish idempotency, Terraform plan safety, or publication safety.

## Rejected alternatives

- **Trust authenticated JSON:** caller authentication is not cloud-state attestation.
- **Trust the Security Hub event without a live lookup:** the rule may already be removed or changed.
- **Use the EventBridge account as the target account:** aggregation can make these accounts differ.
- **Accept CSPM and V2 by source name:** the payload schemas and detail types are not interchangeable.
- **Patch every public rule returned:** multiple/broad rules may map to different Terraform owners and
  need an explicit multi-rule design.

The detailed executable contract and AWS references are in
[`../trusted-finding-provenance.md`](../trusted-finding-provenance.md).
