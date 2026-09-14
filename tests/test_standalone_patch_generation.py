from pathlib import Path

from infraguard.models import Decision, SecurityFinding, SecurityGroupRule
from infraguard.patches import PatchError, generate_standalone_public_ssh_patch, write_patch
from infraguard.pipeline import plan_from_terraform

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


def test_generates_patch_for_legacy_standalone_rule(tmp_path: Path) -> None:
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

    assert decision.decision == Decision.AUTO_PR
    patch = generate_standalone_public_ssh_patch(decision)

    assert patch.file_path == str(target_file)
    assert '"0.0.0.0/0"' in patch.before
    assert '"0.0.0.0/0"' not in patch.after
    assert '"10.20.30.40/32"' in patch.after
    assert patch.resource_address == "aws_security_group_rule.ssh_public"
    assert '-  cidr_blocks       = ["0.0.0.0/0"]' in patch.diff
    assert '+  cidr_blocks       = ["10.20.30.40/32"]' in patch.diff


def test_generates_patch_for_vpc_ingress_rule(tmp_path: Path) -> None:
    source = FIXTURES / "vpc_ingress_public_ssh" / "security-groups.tf"
    target_dir = tmp_path / "terraform"
    target_dir.mkdir()
    target_file = target_dir / "security-groups.tf"
    target_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=target_dir,
        replacement_source="10.20.30.40/32",
    )

    assert decision.decision == Decision.AUTO_PR
    patch = generate_standalone_public_ssh_patch(decision)

    assert '"0.0.0.0/0"' not in patch.after
    assert 'cidr_ipv4         = "10.20.30.40/32"' in patch.after
    assert patch.resource_address == "aws_vpc_security_group_ingress_rule.ssh_public"
    assert '-  cidr_ipv4         = "0.0.0.0/0"' in patch.diff
    assert '+  cidr_ipv4         = "10.20.30.40/32"' in patch.diff


def test_write_patch_updates_target_file(tmp_path: Path) -> None:
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
    write_patch(patch)

    updated = target_file.read_text(encoding="utf-8")
    assert '"0.0.0.0/0"' not in updated
    assert '"10.20.30.40/32"' in updated


def test_patch_changes_cidr_attribute_not_description(tmp_path: Path) -> None:
    target_file = tmp_path / "security-groups.tf"
    target_file.write_text(
        """resource "aws_security_group_rule" "ssh_public" {
  description       = "Temporary source 0.0.0.0/0"
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-1234567890abcdef0"
}
""",
        encoding="utf-8",
    )
    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=tmp_path,
        replacement_source="10.20.30.40/32",
    )

    patch = generate_standalone_public_ssh_patch(decision)

    assert 'description       = "Temporary source 0.0.0.0/0"' in patch.after
    assert 'cidr_blocks       = ["10.20.30.40/32"]' in patch.after


def test_refuses_patch_when_decision_requires_manual_review() -> None:
    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=FIXTURES / "no_public_ssh",
        replacement_source="10.20.30.40/32",
    )

    assert decision.decision == Decision.MANUAL_REVIEW
    try:
        generate_standalone_public_ssh_patch(decision)
    except PatchError as exc:
        assert "cannot generate patch" in str(exc)
    else:
        raise AssertionError("expected PatchError")
