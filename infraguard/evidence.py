from __future__ import annotations

from infraguard.models import PatchValidation, RemediationDecision, TerraformPatch


def build_evidence_json(
    decision: RemediationDecision,
    patch: TerraformPatch,
    validation: PatchValidation,
) -> dict[str, object]:
    finding = decision.finding
    provenance = finding.provenance
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
        "finding_provenance": (
            {
                "method": provenance.method.value,
                "transport_event_id": provenance.transport_event_id,
                "security_hub_finding_id": provenance.security_hub_finding_id,
                "product_arn": provenance.product_arn,
                "source_account_id": provenance.source_account_id,
                "verifier_account_id": provenance.verifier_account_id,
                "region": provenance.region,
                "resource_id": provenance.resource_id,
                "security_group_rule_id": provenance.security_group_rule_id,
                "observed_at": provenance.observed_at.isoformat(),
                "verified_at": provenance.verified_at.isoformat(),
                "aws_request_ids": list(provenance.aws_request_ids),
                "rule_fingerprint": provenance.rule_fingerprint,
            }
            if provenance
            else None
        ),
        "decision": decision.decision.value,
        "decision_reason": decision.reason,
        "ownership": decision.ownership.value,
        "terraform_resource": {
            "address": terraform_resource.address if terraform_resource else None,
            "file_path": terraform_resource.file_path if terraform_resource else None,
            "ownership_proof": (
                terraform_resource.ownership_proof.value
                if terraform_resource and terraform_resource.ownership_proof
                else None
            ),
            "state_rule_id": (
                terraform_resource.state_rule_id if terraform_resource else None
            ),
            "state_lineage": (
                terraform_resource.state_lineage if terraform_resource else None
            ),
            "state_serial": (
                terraform_resource.state_serial if terraform_resource else None
            ),
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
    rule = decision.finding.rule
    offending_rule = (
        f"{rule.direction} {rule.protocol} {rule.from_port}-{rule.to_port} from {rule.source}"
    )
    provenance = decision.finding.provenance
    verification_method = provenance.method.value if provenance else "unverified"
    security_group_rule_id = provenance.security_group_rule_id if provenance else "unknown"
    terraform_resource = decision.terraform_resource
    ownership_proof = (
        terraform_resource.ownership_proof.value
        if terraform_resource and terraform_resource.ownership_proof
        else "unproven"
    )
    state_rule_id = (
        terraform_resource.state_rule_id if terraform_resource else "unknown"
    )

    return f"""## InfraGuard Remediation Evidence

### Finding

| Field | Value |
|---|---|
| Alert ID | `{evidence["alert_id"]}` |
| Account | `{evidence["account_id"]}` |
| Region | `{evidence["region"]}` |
| Resource | `{evidence["resource_type"]}` / `{evidence["resource_id"]}` |
| Offending Rule | `{offending_rule}` |
| AWS Rule ID | `{security_group_rule_id}` |
| Verification | `{verification_method}` |

### Decision

| Field | Value |
|---|---|
| Decision | `{evidence["decision"]}` |
| Reason | {evidence["decision_reason"]} |
| Ownership | `{evidence["ownership"]}` |
| Ownership Proof | `{ownership_proof}` |
| State Rule ID | `{state_rule_id}` |
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
