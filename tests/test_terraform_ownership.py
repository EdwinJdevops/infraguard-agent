from pathlib import Path

import pytest

from infraguard.models import Ownership, SecurityFinding, SecurityGroupRule
from infraguard.ownership import OwnershipError, classify_security_group_ownership

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


def test_classifies_legacy_standalone_security_group_rule() -> None:
    ref = classify_security_group_ownership(
        finding=public_ssh_finding(),
        terraform_root=FIXTURES / "standalone_public_ssh",
    )

    assert ref is not None
    assert ref.address == "aws_security_group_rule.ssh_public"
    assert ref.ownership == Ownership.TERRAFORM_STANDALONE_RULE


def test_classifies_vpc_ingress_security_group_rule() -> None:
    ref = classify_security_group_ownership(
        finding=public_ssh_finding(),
        terraform_root=FIXTURES / "vpc_ingress_public_ssh",
    )

    assert ref is not None
    assert ref.address == "aws_vpc_security_group_ingress_rule.ssh_public"
    assert ref.ownership == Ownership.TERRAFORM_STANDALONE_RULE


def test_classifies_inline_security_group_rule() -> None:
    ref = classify_security_group_ownership(
        finding=public_ssh_finding(),
        terraform_root=FIXTURES / "inline_public_ssh",
        terraform_state_path=FIXTURES / "inline_public_ssh" / "terraform-state.json",
    )

    assert ref is not None
    assert ref.address == "aws_security_group.app"
    assert ref.ownership == Ownership.TERRAFORM_INLINE_RULE


def test_inline_security_group_rule_without_state_is_not_proven() -> None:
    ref = classify_security_group_ownership(
        finding=public_ssh_finding(),
        terraform_root=FIXTURES / "inline_public_ssh",
    )

    assert ref is None


def test_returns_none_when_no_public_ssh_match_exists() -> None:
    ref = classify_security_group_ownership(
        finding=public_ssh_finding(),
        terraform_root=FIXTURES / "no_public_ssh",
    )

    assert ref is None


def test_reference_does_not_prove_security_group_without_state(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """resource "aws_security_group_rule" "ssh_public" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}
""",
        encoding="utf-8",
    )

    assert classify_security_group_ownership(public_ssh_finding(), tmp_path) is None


def test_reference_is_proven_by_matching_state(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """resource "aws_security_group" "app" { name = "app" }
resource "aws_security_group_rule" "ssh_public" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}
""",
        encoding="utf-8",
    )
    state = tmp_path / "terraform.tfstate"
    state.write_text(
        '{"resources":[{"mode":"managed","type":"aws_security_group","name":"app",'
        '"instances":[{"attributes":{"id":"sg-1234567890abcdef0"}}]}]}',
        encoding="utf-8",
    )

    resource = classify_security_group_ownership(public_ssh_finding(), tmp_path, state)

    assert resource is not None
    assert resource.address == "aws_security_group_rule.ssh_public"


def test_ambiguous_owners_are_rejected(tmp_path: Path) -> None:
    fixture = (FIXTURES / "standalone_public_ssh" / "security-groups.tf").read_text(
        encoding="utf-8"
    )
    (tmp_path / "one.tf").write_text(fixture, encoding="utf-8")
    (tmp_path / "two.tf").write_text(
        fixture.replace("ssh_public", "ssh_public_duplicate"), encoding="utf-8"
    )

    with pytest.raises(OwnershipError, match="multiple Terraform resources"):
        classify_security_group_ownership(public_ssh_finding(), tmp_path)


def test_malformed_hcl_is_not_silently_ignored(tmp_path: Path) -> None:
    (tmp_path / "broken.tf").write_text(
        'resource "aws_security_group" "broken" {', encoding="utf-8"
    )

    with pytest.raises(OwnershipError, match="failed to parse Terraform file"):
        classify_security_group_ownership(public_ssh_finding(), tmp_path)


def test_malformed_state_is_not_silently_ignored(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("", encoding="utf-8")
    state = tmp_path / "terraform.tfstate"
    state.write_text("{not-json", encoding="utf-8")

    with pytest.raises(OwnershipError, match="failed to parse Terraform state"):
        classify_security_group_ownership(public_ssh_finding(), tmp_path, state)


def test_terraform_symlink_cannot_escape_configured_root(tmp_path: Path) -> None:
    terraform_root = tmp_path / "terraform"
    terraform_root.mkdir()
    outside = tmp_path / "outside.tf"
    outside.write_text(
        (FIXTURES / "standalone_public_ssh" / "security-groups.tf").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    (terraform_root / "escape.tf").symlink_to(outside)

    with pytest.raises(OwnershipError, match="symlinks are not supported"):
        classify_security_group_ownership(public_ssh_finding(), terraform_root)


@pytest.mark.parametrize(
    ("resource_type", "source_attribute"),
    [
        ("aws_security_group_rule", 'ipv6_cidr_blocks = ["::/0"]'),
        ("aws_vpc_security_group_ingress_rule", 'cidr_ipv6 = "::/0"'),
    ],
)
def test_classifies_ipv6_standalone_rule(
    tmp_path: Path, resource_type: str, source_attribute: str
) -> None:
    protocol_attribute = "protocol" if resource_type == "aws_security_group_rule" else "ip_protocol"
    type_attribute = 'type = "ingress"' if resource_type == "aws_security_group_rule" else ""
    (tmp_path / "main.tf").write_text(
        f'''resource "{resource_type}" "ssh_public" {{
  {type_attribute}
  from_port         = 22
  to_port           = 22
  {protocol_attribute} = "tcp"
  {source_attribute}
  security_group_id = "sg-1234567890abcdef0"
}}
''',
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
    )

    ref = classify_security_group_ownership(ipv6_finding, tmp_path)

    assert ref is not None
    assert ref.address == f"{resource_type}.ssh_public"
