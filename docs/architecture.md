# InfraGuard Production Architecture

InfraGuard is a GitOps-first remediation PR system for cloud security findings.
It does not apply infrastructure changes directly. It produces reviewed pull requests with evidence.

## Core Flow

1. Normalize cloud security finding.
2. Correlate the affected cloud resource with Terraform state and source files.
3. Classify Terraform ownership.
4. Make a policy decision: auto PR, manual review, or reject.
5. Generate a remediation patch only when ownership and replacement policy are proven.
6. Validate the patch before PR creation.
7. Open a PR with risk, evidence, validation output, and reviewer checklist.
8. Verify the cloud finding after merge/deploy.

The implemented baseline now covers steps 2-4 for public SSH findings:

- parses Terraform HCL with `python-hcl2`;
- recognizes legacy `aws_security_group_rule`;
- recognizes newer `aws_vpc_security_group_ingress_rule`;
- recognizes inline `aws_security_group` ingress only when Terraform state maps the resource address to the affected `sg-*` ID;
- returns `manual_review` when ownership is not proven.

## Ownership Classes

| Ownership | Meaning | Automation Behavior |
|---|---|---|
| `terraform_standalone_rule` | The offending rule is managed as a standalone Terraform security group rule resource. | PR can be generated after policy validation. |
| `terraform_inline_rule` | The offending rule is inside an `aws_security_group` inline ingress block and Terraform state proves that resource maps to the affected `sg-*` ID. | PR can be generated after source edit support is implemented. |
| `unmanaged_remote_rule` | The rule exists in AWS but is not proven in Terraform. | Manual review only. |
| `unknown` | InfraGuard cannot prove ownership. | Manual review only. |

## First Supported Remediation

The first production capability is public SSH ingress remediation for AWS security groups:

- direction: ingress
- protocol: tcp
- port: 22
- source: `0.0.0.0/0` or `::/0`

Automatic PR creation requires:

- public SSH detected;
- Terraform ownership proven;
- approved non-public replacement source provided;
- validation passes.

## Non-Goals For The First Production Slice

- Direct AWS mutation.
- Direct Terraform apply.
- Multi-cloud remediation.
- Broad S3/IAM/RDS remediation.
- LLM-generated HCL without deterministic validation.
