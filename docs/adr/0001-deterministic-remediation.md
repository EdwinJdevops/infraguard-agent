# ADR 0001: deterministic remediation and separated publication

- Status: accepted
- Date: 2026-09-14

## Context

The hackathon prototype coupled model reasoning, generated Terraform, and GitHub behavior. The
original PR demonstrated the core danger: adding a private SSH rule did not remove the existing
public rule, yet looked superficially like a remediation.

Infrastructure changes require reproducible authorization, ownership, mutation, and verification
decisions. A confidence score or natural-language explanation cannot prove those properties.

## Decision

1. LLM output is excluded from ownership, authorization, policy, patch generation, validation, and
   publication gates.
2. Automatic scope is capability-specific and deny-by-default.
3. Unknown, ambiguous, malformed, or unsupported evidence fails closed.
4. The API is a read-only planner. Repository publication will be a separate short-lived component
   with separate credentials.
5. A PR is never treated as remediation completion. Completion requires independent verification
   after the existing IaC pipeline deploys the reviewed change.
6. The historical model/publisher prototype is removed from the shipping tree and remains
   recoverable from Git history.

## Consequences

Positive:

- decisions and diffs are reproducible and testable;
- the planner has no external write credential;
- unsupported Terraform forms produce false negatives rather than unsafe edits;
- evidence can be reviewed without trusting a model.

Costs:

- initial remediation coverage is narrow;
- Terraform-native plan evaluation and state provenance still require substantial engineering;
- publication and verification need durable workflow infrastructure;
- natural-language assistance can only explain results, not authorize changes.

## Rejected alternatives

- **Confidence threshold for generated HCL:** a numeric score is not a proof of ownership or safety.
- **Direct AWS mutation:** bypasses source-of-truth review and can create Terraform drift.
- **Publisher inside the API:** combines untrusted intake and repository write authority in one
  blast radius.
- **Add a second restricted rule:** AWS rules are additive, so the original public exposure remains.
