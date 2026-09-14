from __future__ import annotations

from collections.abc import Collection
from pathlib import Path

from infraguard.evidence import build_evidence_json, build_pr_markdown
from infraguard.models import Decision, RemediationRun, SecurityFinding
from infraguard.patches import generate_standalone_public_ssh_patch
from infraguard.pipeline import plan_from_terraform
from infraguard.validation import validate_public_ssh_patch


def run_public_ssh_remediation(
    finding: SecurityFinding,
    terraform_root: Path,
    replacement_source: str | None,
    terraform_state_path: Path | None = None,
    allowed_replacement_sources: Collection[str] | None = None,
) -> RemediationRun:
    decision = plan_from_terraform(
        finding=finding,
        terraform_root=terraform_root,
        replacement_source=replacement_source,
        terraform_state_path=terraform_state_path,
        allowed_replacement_sources=allowed_replacement_sources,
    )
    if decision.decision != Decision.AUTO_PR:
        return RemediationRun(
            decision=decision,
            patch=None,
            validation=None,
            evidence_json=None,
            pr_markdown=None,
        )

    patch = generate_standalone_public_ssh_patch(decision)
    validation = validate_public_ssh_patch(patch)
    if not validation.passed:
        return RemediationRun(
            decision=decision,
            patch=patch,
            validation=validation,
            evidence_json=None,
            pr_markdown=None,
        )

    return RemediationRun(
        decision=decision,
        patch=patch,
        validation=validation,
        evidence_json=build_evidence_json(decision, patch, validation),
        pr_markdown=build_pr_markdown(decision, patch, validation),
    )
