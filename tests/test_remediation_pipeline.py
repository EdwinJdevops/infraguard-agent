from pathlib import Path

from infraguard.models import Decision, Ownership, SecurityFinding, SecurityGroupRule
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


def test_pipeline_allows_auto_pr_for_proven_standalone_rule() -> None:
    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=FIXTURES / "standalone_public_ssh",
        replacement_source="203.0.113.10/32",
    )

    assert decision.decision == Decision.AUTO_PR
    assert decision.ownership == Ownership.TERRAFORM_STANDALONE_RULE
    assert decision.terraform_resource is not None
    assert decision.terraform_resource.address == "aws_security_group_rule.ssh_public"


def test_pipeline_requires_manual_review_when_ownership_is_unknown() -> None:
    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=FIXTURES / "no_public_ssh",
        replacement_source="203.0.113.10/32",
    )

    assert decision.decision == Decision.MANUAL_REVIEW
    assert decision.ownership == Ownership.UNKNOWN
    assert decision.terraform_resource is None


def test_pipeline_proves_inline_rule_only_with_state() -> None:
    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=FIXTURES / "inline_public_ssh",
        terraform_state_path=FIXTURES / "inline_public_ssh" / "terraform.tfstate",
        replacement_source="203.0.113.10/32",
    )

    assert decision.decision == Decision.AUTO_PR
    assert decision.ownership == Ownership.TERRAFORM_INLINE_RULE
    assert decision.terraform_resource is not None
    assert decision.terraform_resource.address == "aws_security_group.app"


def test_pipeline_rejects_public_replacement_source_even_with_ownership() -> None:
    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=FIXTURES / "standalone_public_ssh",
        replacement_source="0.0.0.0/0",
    )

    assert decision.decision == Decision.REJECT
    assert "public IPv4" in decision.reason

