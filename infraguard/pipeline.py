from __future__ import annotations

from pathlib import Path

from infraguard.models import RemediationDecision, SecurityFinding
from infraguard.ownership import classify_security_group_ownership
from infraguard.remediation import plan_public_ssh_remediation


def plan_from_terraform(
    finding: SecurityFinding,
    terraform_root: Path,
    replacement_source: str | None,
    terraform_state_path: Path | None = None,
) -> RemediationDecision:
    terraform_resource = classify_security_group_ownership(
        finding=finding,
        terraform_root=terraform_root,
        terraform_state_path=terraform_state_path,
    )
    return plan_public_ssh_remediation(
        finding=finding,
        terraform_resource=terraform_resource,
        replacement_source=replacement_source,
    )

