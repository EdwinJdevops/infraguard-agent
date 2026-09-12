from pathlib import Path

from infraguard.models import Decision, SecurityFinding, SecurityGroupRule
from infraguard.runbook import run_public_ssh_remediation


FIXTURES = Path(__file__).parent / "fixtures" / "terraform"


def public_ssh_finding() -> SecurityFinding:
    return SecurityFinding(
        alert_id="alert-001",
        provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_security_group",
        resource_id="sg-1234567890abcdef0",
        rule=SecurityGroupRule(
            direction="ingress",
            protocol="tcp",
            from_port=22,
            to_port=22,
            source="0.0.0.0/0",
        ),
    )


def test_runbook_produces_patch_validation_and_evidence(tmp_path: Path) -> None:
    source = FIXTURES / "standalone_public_ssh" / "security-groups.tf"
    target_dir = tmp_path / "terraform"
    target_dir.mkdir()
    target_file = target_dir / "security-groups.tf"
    target_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    run = run_public_ssh_remediation(
        finding=public_ssh_finding(),
        terraform_root=target_dir,
        replacement_source="203.0.113.10/32",
    )

    assert run.decision.decision == Decision.AUTO_PR
    assert run.patch is not None
    assert run.validation is not None
    assert run.validation.passed is True
    assert run.evidence_json is not None
    assert run.evidence_json["decision"] == "auto_pr"
    assert run.pr_markdown is not None
    assert "InfraGuard Remediation Evidence" in run.pr_markdown


def test_runbook_returns_manual_review_without_patch_when_ownership_unknown() -> None:
    run = run_public_ssh_remediation(
        finding=public_ssh_finding(),
        terraform_root=FIXTURES / "no_public_ssh",
        replacement_source="203.0.113.10/32",
    )

    assert run.decision.decision == Decision.MANUAL_REVIEW
    assert run.patch is None
    assert run.validation is None
    assert run.evidence_json is None
    assert run.pr_markdown is None

