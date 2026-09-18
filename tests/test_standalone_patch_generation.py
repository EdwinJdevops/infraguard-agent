from pathlib import Path
from shutil import copyfile

from infraguard.models import Decision, SecurityFinding, SecurityGroupRule
from infraguard.patches import PatchError, generate_standalone_public_ssh_patch, write_patch
from infraguard.pipeline import plan_from_terraform
from infraguard.validation import validate_public_ssh_patch
from tests.factories import verified_provenance

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
        provenance=verified_provenance(),
    )


def test_generates_patch_for_legacy_standalone_rule(tmp_path: Path) -> None:
    source = FIXTURES / "standalone_public_ssh" / "security-groups.tf"
    target_dir = tmp_path / "terraform"
    target_dir.mkdir()
    target_file = target_dir / "security-groups.tf"
    target_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    copyfile(
        FIXTURES / "standalone_public_ssh" / "terraform-state.json",
        target_dir / "terraform-state.json",
    )

    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=target_dir,
        terraform_state_path=target_dir / "terraform-state.json",
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
    copyfile(
        FIXTURES / "vpc_ingress_public_ssh" / "terraform-state.json",
        target_dir / "terraform-state.json",
    )

    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=target_dir,
        terraform_state_path=target_dir / "terraform-state.json",
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
    copyfile(
        FIXTURES / "standalone_public_ssh" / "terraform-state.json",
        target_dir / "terraform-state.json",
    )

    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=target_dir,
        terraform_state_path=target_dir / "terraform-state.json",
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
  description       = "0.0.0.0/0"
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
    (tmp_path / "terraform-state.json").write_text(
        (FIXTURES / "standalone_public_ssh" / "terraform-state.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=tmp_path,
        terraform_state_path=tmp_path / "terraform-state.json",
        replacement_source="10.20.30.40/32",
    )

    patch = generate_standalone_public_ssh_patch(decision)

    assert 'description       = "0.0.0.0/0"' in patch.after
    assert 'cidr_blocks       = ["10.20.30.40/32"]' in patch.after


def test_generates_and_validates_ipv6_vpc_ingress_patch(tmp_path: Path) -> None:
    target_file = tmp_path / "security-groups.tf"
    target_file.write_text(
        """resource "aws_vpc_security_group_ingress_rule" "ssh_public" {
  security_group_id = "sg-1234567890abcdef0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv6         = "::/0"
}
""",
        encoding="utf-8",
    )
    (tmp_path / "terraform-state.json").write_text(
        (FIXTURES / "vpc_ingress_public_ssh" / "terraform-state.json")
        .read_text(encoding="utf-8")
        .replace('"cidr_ipv4": "0.0.0.0/0"', '"cidr_ipv6": "::/0"'),
        encoding="utf-8",
    )
    finding = public_ssh_finding()
    ipv6_finding = SecurityFinding(
        alert_id=finding.alert_id,
        provider=finding.provider,
        account_id=finding.account_id,
        region=finding.region,
        resource_type=finding.resource_type,
        resource_id=finding.resource_id,
        rule=SecurityGroupRule(
            direction="ingress",
            protocol="tcp",
            from_port=22,
            to_port=22,
            source="::/0",
        ),
        provenance=verified_provenance(source="::/0"),
    )
    decision = plan_from_terraform(
        finding=ipv6_finding,
        terraform_root=tmp_path,
        terraform_state_path=tmp_path / "terraform-state.json",
        replacement_source="fd00:1234::/64",
    )

    patch = generate_standalone_public_ssh_patch(decision)

    assert 'cidr_ipv6         = "::/0"' in patch.before
    assert 'cidr_ipv6         = "fd00:1234::/64"' in patch.after
    assert validate_public_ssh_patch(patch).passed is True


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
