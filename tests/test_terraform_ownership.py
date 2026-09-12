from pathlib import Path

from infraguard.models import Ownership, SecurityFinding, SecurityGroupRule
from infraguard.ownership import classify_security_group_ownership


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
        terraform_state_path=FIXTURES / "inline_public_ssh" / "terraform.tfstate",
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
