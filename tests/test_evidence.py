from pathlib import Path

from infraguard.evidence import build_evidence_json, build_pr_markdown
from infraguard.models import SecurityFinding, SecurityGroupRule
from infraguard.patches import generate_standalone_public_ssh_patch
from infraguard.pipeline import plan_from_terraform
from infraguard.validation import validate_public_ssh_patch

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


def test_builds_machine_readable_evidence(tmp_path: Path) -> None:
    source = FIXTURES / "standalone_public_ssh" / "security-groups.tf"
    target_dir = tmp_path / "terraform"
    target_dir.mkdir()
    target_file = target_dir / "security-groups.tf"
    target_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    decision = plan_from_terraform(public_ssh_finding(), target_dir, "10.20.30.40/32")
    patch = generate_standalone_public_ssh_patch(decision)
    validation = validate_public_ssh_patch(patch)
    evidence = build_evidence_json(decision, patch, validation)

    assert evidence["alert_id"] == "alert-001"
    assert evidence["decision"] == "auto_pr"
    assert evidence["ownership"] == "terraform_standalone_rule"
    assert evidence["replacement_source"] == "10.20.30.40/32"
    assert evidence["validation"]["passed"] is True  # type: ignore[index]


def test_builds_pr_markdown_with_diff_and_checks(tmp_path: Path) -> None:
    source = FIXTURES / "standalone_public_ssh" / "security-groups.tf"
    target_dir = tmp_path / "terraform"
    target_dir.mkdir()
    target_file = target_dir / "security-groups.tf"
    target_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    decision = plan_from_terraform(public_ssh_finding(), target_dir, "10.20.30.40/32")
    patch = generate_standalone_public_ssh_patch(decision)
    validation = validate_public_ssh_patch(patch)
    markdown = build_pr_markdown(decision, patch, validation)

    assert "## InfraGuard Remediation Evidence" in markdown
    assert "`auto_pr`" in markdown
    assert "`terraform_standalone_rule`" in markdown
    assert "- [x] `after_removes_target_public_ssh`" in markdown
    assert '-  cidr_blocks       = ["0.0.0.0/0"]' in markdown
    assert '+  cidr_blocks       = ["10.20.30.40/32"]' in markdown

