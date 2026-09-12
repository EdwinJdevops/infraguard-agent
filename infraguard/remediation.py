from __future__ import annotations

from infraguard.models import (
    Decision,
    Ownership,
    RemediationDecision,
    SecurityFinding,
    TerraformResourceRef,
)
from infraguard.policy import PolicyError, validate_replacement_source


def plan_public_ssh_remediation(
    finding: SecurityFinding,
    terraform_resource: TerraformResourceRef | None,
    replacement_source: str | None,
) -> RemediationDecision:
    if finding.provider != "aws":
        return RemediationDecision(
            decision=Decision.REJECT,
            reason="only aws findings are supported by this remediation planner",
            finding=finding,
            ownership=Ownership.UNKNOWN,
            replacement_source=None,
        )

    if finding.resource_type != "aws_security_group":
        return RemediationDecision(
            decision=Decision.REJECT,
            reason="only aws_security_group public ssh findings are supported",
            finding=finding,
            ownership=Ownership.UNKNOWN,
            replacement_source=None,
        )

    if not finding.rule.is_public_ssh():
        return RemediationDecision(
            decision=Decision.REJECT,
            reason="finding is not public ssh ingress",
            finding=finding,
            ownership=terraform_resource.ownership if terraform_resource else Ownership.UNKNOWN,
            replacement_source=None,
        )

    if terraform_resource is None or terraform_resource.ownership == Ownership.UNKNOWN:
        return RemediationDecision(
            decision=Decision.MANUAL_REVIEW,
            reason="terraform ownership is unknown, so automatic patching is unsafe",
            finding=finding,
            ownership=Ownership.UNKNOWN,
            replacement_source=None,
            evidence=["public_ssh_detected"],
        )

    if terraform_resource.ownership == Ownership.UNMANAGED_REMOTE_RULE:
        return RemediationDecision(
            decision=Decision.MANUAL_REVIEW,
            reason="rule exists remotely but is not proven terraform-managed",
            finding=finding,
            ownership=Ownership.UNMANAGED_REMOTE_RULE,
            replacement_source=None,
            evidence=["public_ssh_detected", "unmanaged_remote_rule"],
            terraform_resource=terraform_resource,
        )

    if replacement_source is None:
        return RemediationDecision(
            decision=Decision.MANUAL_REVIEW,
            reason="approved replacement source is required before opening a remediation PR",
            finding=finding,
            ownership=terraform_resource.ownership,
            replacement_source=None,
            evidence=["public_ssh_detected", "terraform_ownership_proven"],
            terraform_resource=terraform_resource,
        )

    try:
        normalized_source = validate_replacement_source(replacement_source)
    except PolicyError as exc:
        return RemediationDecision(
            decision=Decision.REJECT,
            reason=str(exc),
            finding=finding,
            ownership=terraform_resource.ownership,
            replacement_source=None,
            evidence=["public_ssh_detected", "terraform_ownership_proven", "replacement_source_rejected"],
            terraform_resource=terraform_resource,
        )

    return RemediationDecision(
        decision=Decision.AUTO_PR,
        reason="public ssh rule is terraform-managed and replacement source passed policy",
        finding=finding,
        ownership=terraform_resource.ownership,
        replacement_source=normalized_source,
        evidence=["public_ssh_detected", "terraform_ownership_proven", "replacement_source_approved"],
        terraform_resource=terraform_resource,
    )

