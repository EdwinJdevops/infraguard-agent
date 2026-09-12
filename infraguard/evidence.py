from __future__ import annotations

from infraguard.models import PatchValidation, RemediationDecision, TerraformPatch


def build_evidence_json(
    decision: RemediationDecision,
    patch: TerraformPatch,
    validation: PatchValidation,
) -> dict[str, object]:
    finding = decision.finding
    terraform_resource = decision.terraform_resource
    return {
        "alert_id": finding.alert_id,
        "provider": finding.provider,
        "account_id": finding.account_id,
        "region": finding.region,
        "resource_type": finding.resource_type,
        "resource_id": finding.resource_id,
        "offending_rule": {
            "direction": finding.rule.direction,
            "protocol": finding.rule.protocol,
            "from_port": finding.rule.from_port,
            "to_port": finding.rule.to_port,
            "source": finding.rule.source,
        },
        "decision": decision.decision.value,
        "decision_reason": decision.reason,
        "ownership": decision.ownership.value,
        "terraform_resource": {
            "address": terraform_resource.address if terraform_resource else None,
            "file_path": terraform_resource.file_path if terraform_resource else None,
        },
        "replacement_source": decision.replacement_source,
        "patch": {
            "file_path": patch.file_path,
            "resource_address": patch.resource_address,
            "summary": patch.summary,
            "diff": patch.diff,
        },
        "validation": validation.to_evidence(),
    }


def build_pr_markdown(
    decision: RemediationDecision,
    patch: TerraformPatch,
    validation: PatchValidation,
) -> str:
    evidence = build_evidence_json(decision, patch, validation)
    checks = evidence["validation"]["checks"]  # type: ignore[index]
    check_lines = "\n".join(
        f"- [{'x' if passed else ' '}] `{name}`"
        for name, passed in checks.items()  # type: ignore[union-attr]
    )
    errors = evidence["validation"]["errors"]  # type: ignore[index]
    error_section = "None" if not errors else "\n".join(f"- {error}" for error in errors)  # type: ignore[truthy-function]

    return f"""## InfraGuard Remediation Evidence

### Finding

| Field | Value |
|---|---|
| Alert ID | `{evidence["alert_id"]}` |
| Account | `{evidence["account_id"]}` |
| Region | `{evidence["region"]}` |
| Resource | `{evidence["resource_type"]}` / `{evidence["resource_id"]}` |
| Offending Rule | `{decision.finding.rule.direction} {decision.finding.rule.protocol} {decision.finding.rule.from_port}-{decision.finding.rule.to_port} from {decision.finding.rule.source}` |

### Decision

| Field | Value |
|---|---|
| Decision | `{evidence["decision"]}` |
| Reason | {evidence["decision_reason"]} |
| Ownership | `{evidence["ownership"]}` |
| Terraform Resource | `{patch.resource_address}` |
| Replacement Source | `{decision.replacement_source}` |

### Validation

Passed: `{str(validation.passed).lower()}`

{check_lines}

Errors: {error_section}

### Patch

```diff
{patch.diff}```
"""

