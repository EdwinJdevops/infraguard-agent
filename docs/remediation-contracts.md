# Remediation Contracts

InfraGuard remediations are contracts, not free-form model outputs.

## Decision Contract

Every remediation plan must resolve to one of three decisions:

| Decision | Meaning |
|---|---|
| `auto_pr` | Safe to open a pull request because ownership and policy were proven. |
| `manual_review` | A human must decide because InfraGuard lacks enough evidence. |
| `reject` | The requested remediation violates policy or is outside supported scope. |

## Public SSH Contract

InfraGuard may open an automatic PR for public SSH only when all conditions are true:

1. Provider is AWS.
2. Resource type is `aws_security_group`.
3. Rule is ingress TCP/22.
4. Source is `0.0.0.0/0` or `::/0`.
5. Terraform ownership is proven. Inline security group ownership requires Terraform state mapping from resource address to the affected `sg-*` ID.
6. Replacement source is supplied and is not public.

If any condition fails, InfraGuard must not open an automatic remediation PR.

## Evidence Required In PR

- Alert ID.
- Account and region.
- Affected security group ID.
- Offending rule.
- Terraform resource address.
- Ownership classification.
- Replacement source.
- Validation output.
- Human reviewer checklist.
