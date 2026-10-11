from dataclasses import replace

import pytest

from infraguard.models import (
    Decision,
    Ownership,
    OwnershipProof,
    SecurityFinding,
    SecurityGroupRule,
    TerraformResourceRef,
)
from infraguard.remediation import plan_public_ssh_remediation
from tests.factories import verified_provenance


def proven_standalone_ref(**kwargs) -> TerraformResourceRef:
    return TerraformResourceRef(
        ownership_proof=OwnershipProof.TERRAFORM_STATE_RULE_ID,
        state_rule_id="sgr-1234567890abcdef0",
        state_lineage="synthetic-planner-fixture",
        state_serial=1,
        **kwargs,
    )


@pytest.mark.parametrize("changes", [
    {"ownership_proof": None}, {"state_rule_id": "sgr-00000000000000000"},
    {"state_lineage": None}, {"state_serial": None}, {"state_serial": True},
    {"file_path": None},
])
def test_standalone_label_without_matching_state_evidence_is_manual(changes: dict) -> None:
    ref = proven_standalone_ref(
        address="aws_security_group_rule.ssh_public",
        ownership=Ownership.TERRAFORM_STANDALONE_RULE,
        file_path="security-groups.tf",
    )
    decision = plan_public_ssh_remediation(
        public_ssh_finding(), replace(ref, **changes), "10.20.30.40/32"
    )
    assert decision.decision == Decision.MANUAL_REVIEW
    assert not decision.can_open_pr


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


def test_public_ssh_with_proven_standalone_ownership_can_open_pr() -> None:
    decision = plan_public_ssh_remediation(
        finding=public_ssh_finding(),
        terraform_resource=proven_standalone_ref(
            address="aws_security_group_rule.ssh_public",
            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
            file_path="security-groups.tf",
        ),
        replacement_source="10.20.30.40/32",
    )

    assert decision.decision == Decision.AUTO_PR
    assert decision.can_open_pr is True
    assert decision.replacement_source == "10.20.30.40/32"
    assert "terraform_ownership_proven" in decision.evidence


def test_public_ssh_without_terraform_ownership_requires_manual_review() -> None:
    decision = plan_public_ssh_remediation(
        finding=public_ssh_finding(),
        terraform_resource=None,
        replacement_source="10.20.30.40/32",
    )

    assert decision.decision == Decision.MANUAL_REVIEW
    assert decision.can_open_pr is False
    assert decision.reason == "terraform ownership is unknown, so automatic patching is unsafe"


def test_public_ssh_with_public_replacement_is_rejected() -> None:
    decision = plan_public_ssh_remediation(
        finding=public_ssh_finding(),
        terraform_resource=proven_standalone_ref(
            address="aws_security_group_rule.ssh_public",
            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
            file_path="security-groups.tf",
        ),
        replacement_source="0.0.0.0/0",
    )

    assert decision.decision == Decision.REJECT
    assert decision.can_open_pr is False
    assert "RFC1918" in decision.reason


def test_globally_routable_host_cidr_is_rejected() -> None:
    decision = plan_public_ssh_remediation(
        finding=public_ssh_finding(),
        terraform_resource=proven_standalone_ref(
            address="aws_security_group_rule.ssh_public",
            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
            file_path="security-groups.tf",
        ),
        replacement_source="8.8.8.8/32",
    )

    assert decision.decision == Decision.REJECT
    assert "RFC1918" in decision.reason


def test_ipv6_unique_local_source_is_accepted() -> None:
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
    decision = plan_public_ssh_remediation(
        finding=ipv6_finding,
        terraform_resource=proven_standalone_ref(
            address="aws_security_group_rule.ssh_public",
            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
            file_path="security-groups.tf",
        ),
        replacement_source="fd00:1234::/64",
    )

    assert decision.decision == Decision.AUTO_PR
    assert decision.replacement_source == "fd00:1234::/64"


def test_non_public_ssh_is_rejected() -> None:
    finding = public_ssh_finding()
    non_public = SecurityFinding(
        alert_id=finding.alert_id,
        provider=finding.provider,
        account_id=finding.account_id,
        region=finding.region,
        resource_type=finding.resource_type,
        resource_id=finding.resource_id,
        rule=SecurityGroupRule(
            direction="ingress",
            protocol="tcp",
            from_port=443,
            to_port=443,
            source="0.0.0.0/0",
        ),
    )

    decision = plan_public_ssh_remediation(
        finding=non_public,
        terraform_resource=proven_standalone_ref(
            address="aws_security_group_rule.https_public",
            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
            file_path="security-groups.tf",
        ),
        replacement_source="10.20.30.40/32",
    )

    assert decision.decision == Decision.REJECT
    assert decision.reason == "finding is not public ssh ingress"


def test_replacement_source_must_match_configured_allowlist() -> None:
    decision = plan_public_ssh_remediation(
        finding=public_ssh_finding(),
        terraform_resource=proven_standalone_ref(
            address="aws_security_group_rule.ssh",
            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
            file_path="security-groups.tf",
        ),
        replacement_source="10.20.30.40/32",
        allowed_replacement_sources={"10.99.0.0/16"},
    )

    assert decision.decision == Decision.REJECT
    assert "allowlist" in decision.reason
