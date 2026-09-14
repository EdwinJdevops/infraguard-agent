from dataclasses import replace
from pathlib import Path

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


def test_validates_standalone_patch_evidence(tmp_path: Path) -> None:
    source = FIXTURES / "standalone_public_ssh" / "security-groups.tf"
    target_dir = tmp_path / "terraform"
    target_dir.mkdir()
    target_file = target_dir / "security-groups.tf"
    target_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=target_dir,
        replacement_source="10.20.30.40/32",
    )
    patch = generate_standalone_public_ssh_patch(decision)
    validation = validate_public_ssh_patch(patch)

    assert validation.passed is True
    assert validation.errors == []
    assert validation.checks == {
        "before_target_contains_public_ssh": True,
        "after_parses_as_hcl": True,
        "after_removes_target_public_ssh": True,
        "after_contains_replacement_source": True,
        "target_rule_remains_ssh_ingress": True,
        "only_expected_source_changed": True,
        "diff_is_present": True,
    }


def test_validation_fails_when_after_still_contains_public_source(tmp_path: Path) -> None:
    source = FIXTURES / "standalone_public_ssh" / "security-groups.tf"
    target_dir = tmp_path / "terraform"
    target_dir.mkdir()
    target_file = target_dir / "security-groups.tf"
    target_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=target_dir,
        replacement_source="10.20.30.40/32",
    )
    patch = generate_standalone_public_ssh_patch(decision)
    broken_patch = replace(patch, after=patch.before)
    validation = validate_public_ssh_patch(broken_patch)

    assert validation.passed is False
    assert validation.checks["after_removes_target_public_ssh"] is False


def test_validation_ignores_unrelated_public_rule_in_same_file(tmp_path: Path) -> None:
    target_file = tmp_path / "security-groups.tf"
    target_file.write_text(
        (FIXTURES / "standalone_public_ssh" / "security-groups.tf").read_text(encoding="utf-8")
        + """
resource "aws_security_group_rule" "https_public" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-aaaaaaaaaaaaaaaaa"
}
""",
        encoding="utf-8",
    )
    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=tmp_path,
        replacement_source="10.20.30.40/32",
    )

    validation = validate_public_ssh_patch(generate_standalone_public_ssh_patch(decision))

    assert validation.passed is True
