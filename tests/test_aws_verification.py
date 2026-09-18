from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from infraguard.aws_verification import (
    AwsVerificationError,
    AwsVerificationPolicy,
    AwsVerificationStatus,
    verify_security_hub_cspm_event,
)
from infraguard.models import (
    Decision,
    Ownership,
    SecurityFinding,
    SecurityGroupRule,
    TerraformResourceRef,
)
from infraguard.remediation import plan_public_ssh_remediation

EVENT_ACCOUNT = "210987654321"
TARGET_ACCOUNT = "123456789012"
REGION = "us-east-1"
GROUP_ID = "sg-1234567890abcdef0"
RULE_ID = "sgr-1234567890abcdef0"
NOW = datetime(2026, 9, 14, 12, 5, tzinfo=UTC)


class FakeIdentityClient:
    def __init__(
        self,
        account_id: str = TARGET_ACCOUNT,
        *,
        request_id: str | None = "sts-request-001",
    ) -> None:
        self.account_id = account_id
        self.request_id = request_id

    def get_caller_identity(self) -> dict[str, Any]:
        response: dict[str, Any] = {"Account": self.account_id}
        if self.request_id is not None:
            response["ResponseMetadata"] = {"RequestId": self.request_id}
        return response


class FakeEc2Client:
    def __init__(self, pages: dict[str | None, dict[str, Any]]) -> None:
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def describe_security_group_rules(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(deepcopy(kwargs))
        token = kwargs.get("NextToken")
        if token not in self.pages:
            raise RuntimeError("unexpected page token")
        return deepcopy(self.pages[token])


def event() -> dict[str, Any]:
    return {
        "version": "0",
        "id": "11111111-2222-3333-4444-555555555555",
        "detail-type": "Security Hub Findings - Imported",
        "source": "aws.securityhub",
        "account": EVENT_ACCOUNT,
        "time": "2026-09-14T12:00:00Z",
        "region": REGION,
        "detail": {
            "findings": [
                {
                    "SchemaVersion": "2018-10-08",
                    "Id": "security-hub-finding-001",
                    "ProductArn": (
                        "arn:aws:securityhub:us-east-1::product/aws/securityhub"
                    ),
                    "AwsAccountId": TARGET_ACCOUNT,
                    "Region": REGION,
                    "UpdatedAt": "2026-09-14T12:00:30Z",
                    "RecordState": "ACTIVE",
                    "Workflow": {"Status": "NEW"},
                    "Compliance": {
                        "SecurityControlId": "EC2.13",
                        "Status": "FAILED",
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2SecurityGroup",
                            "Id": (
                                "arn:aws:ec2:us-east-1:123456789012:"
                                "security-group/sg-1234567890abcdef0"
                            ),
                            "Partition": "aws",
                            "Region": REGION,
                            "Details": {
                                "AwsEc2SecurityGroup": {"GroupId": GROUP_ID}
                            },
                        }
                    ],
                }
            ]
        },
    }


def rule(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "SecurityGroupRuleId": RULE_ID,
        "GroupId": GROUP_ID,
        "GroupOwnerId": TARGET_ACCOUNT,
        "IsEgress": False,
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "CidrIpv4": "0.0.0.0/0",
    }
    value.update(overrides)
    return value


def response(
    rules: list[dict[str, Any]],
    *,
    request_id: str | None = "ec2-request-001",
    next_token: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {"SecurityGroupRules": rules}
    if request_id is not None:
        value["ResponseMetadata"] = {"RequestId": request_id}
    if next_token is not None:
        value["NextToken"] = next_token
    return value


def policy(**overrides: Any) -> AwsVerificationPolicy:
    values = {
        "allowed_event_accounts": frozenset({EVENT_ACCOUNT}),
        "max_event_age": timedelta(hours=1),
        "max_future_skew": timedelta(minutes=2),
        "max_pages": 3,
    }
    values.update(overrides)
    return AwsVerificationPolicy(**values)


def verify(
    payload: dict[str, Any] | None = None,
    *,
    identity_client: FakeIdentityClient | None = None,
    ec2_client: FakeEc2Client | None = None,
    verification_policy: AwsVerificationPolicy | None = None,
):
    return verify_security_hub_cspm_event(
        payload if payload is not None else event(),
        identity_client=identity_client or FakeIdentityClient(),
        ec2_client=ec2_client
        or FakeEc2Client({None: response([rule()])}),
        ec2_region=REGION,
        policy=verification_policy or policy(),
        now=NOW,
    )


def test_valid_event_is_bound_to_one_live_rule() -> None:
    ec2 = FakeEc2Client(
        {
            None: response([], request_id="ec2-request-001", next_token="page-2"),
            "page-2": response([rule()], request_id="ec2-request-002"),
        }
    )

    result = verify(ec2_client=ec2)

    assert result.status == AwsVerificationStatus.VERIFIED
    assert result.finding is not None
    assert result.finding.has_verified_provenance() is True
    assert result.finding.rule == SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=22,
        to_port=22,
        source="0.0.0.0/0",
    )
    assert result.finding.provenance is not None
    assert result.finding.provenance.aws_request_ids == (
        "sts-request-001",
        "ec2-request-001",
        "ec2-request-002",
    )
    assert ec2.calls == [
        {
            "Filters": [{"Name": "group-id", "Values": [GROUP_ID]}],
            "MaxResults": 1000,
        },
        {
            "Filters": [{"Name": "group-id", "Values": [GROUP_ID]}],
            "MaxResults": 1000,
            "NextToken": "page-2",
        },
    ]


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("version",), "1"),
        (("detail-type",), "Security Hub Findings - Imported V2"),
        (("source",), "attacker.example"),
        (("detail", "findings", 0, "SchemaVersion"), "2.0"),
        (("detail", "findings", 0, "RecordState"), "ARCHIVED"),
        (("detail", "findings", 0, "Workflow", "Status"), "RESOLVED"),
        (("detail", "findings", 0, "Compliance", "SecurityControlId"), "EC2.14"),
        (("detail", "findings", 0, "Compliance", "Status"), "PASSED"),
        (("detail", "findings", 0, "Resources", 0, "Type"), "AwsEc2Vpc"),
        (("detail", "findings", 0, "Resources", 0, "Region"), "us-west-2"),
    ],
)
def test_untrusted_or_non_actionable_event_is_rejected(
    path: tuple[str | int, ...], value: Any
) -> None:
    payload = event()
    target: Any = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value

    result = verify(payload)

    assert result.status == AwsVerificationStatus.REJECTED
    assert result.finding is None
    assert result.evidence == ("security_hub_event_rejected",)


def test_event_source_account_must_be_allowlisted() -> None:
    result = verify(verification_policy=policy(allowed_event_accounts=frozenset({TARGET_ACCOUNT})))

    assert result.status == AwsVerificationStatus.REJECTED
    assert result.evidence == ("event_account_rejected",)


@pytest.mark.parametrize(
    ("field", "timestamp", "expected_evidence"),
    [
        ("event", "2026-09-14T10:00:00Z", "stale_event_rejected"),
        ("event", "2026-09-14T12:08:00Z", "future_event_rejected"),
        ("finding", "2026-09-14T10:00:00Z", "stale_finding_rejected"),
        ("finding", "2026-09-14T12:08:00Z", "future_finding_rejected"),
    ],
)
def test_stale_and_future_evidence_is_rejected(
    field: str, timestamp: str, expected_evidence: str
) -> None:
    payload = event()
    if field == "event":
        payload["time"] = timestamp
    else:
        payload["detail"]["findings"][0]["UpdatedAt"] = timestamp

    result = verify(payload)

    assert result.status == AwsVerificationStatus.REJECTED
    assert result.evidence == (expected_evidence,)


def test_finding_time_cannot_materially_postdate_event() -> None:
    payload = event()
    payload["detail"]["findings"][0]["UpdatedAt"] = "2026-09-14T12:04:00Z"

    result = verify(payload)

    assert result.status == AwsVerificationStatus.REJECTED
    assert result.evidence == ("finding_event_time_mismatch",)


def test_assumed_role_identity_must_match_target_account() -> None:
    result = verify(identity_client=FakeIdentityClient(EVENT_ACCOUNT))

    assert result.status == AwsVerificationStatus.REJECTED
    assert result.evidence == ("verifier_account_mismatch",)


def test_absent_live_public_ssh_is_resolved() -> None:
    ec2 = FakeEc2Client(
        {
            None: response(
                [
                    rule(CidrIpv4="10.0.0.0/8"),
                    rule(
                        SecurityGroupRuleId="sgr-aaaaaaaaaaaaaaaaa",
                        FromPort=443,
                        ToPort=443,
                    ),
                ]
            )
        }
    )

    result = verify(ec2_client=ec2)

    assert result.status == AwsVerificationStatus.RESOLVED
    assert result.finding is None


def test_all_protocol_public_rule_requires_manual_review() -> None:
    result = verify(ec2_client=FakeEc2Client({None: response([rule(IpProtocol="-1")])}))

    assert result.status == AwsVerificationStatus.MANUAL_REVIEW
    assert "all-protocol" in result.reason


def test_multiple_public_ssh_rules_require_manual_review() -> None:
    second = rule(SecurityGroupRuleId="sgr-aaaaaaaaaaaaaaaaa", CidrIpv4=None, CidrIpv6="::/0")

    result = verify(ec2_client=FakeEc2Client({None: response([rule(), second])}))

    assert result.status == AwsVerificationStatus.MANUAL_REVIEW
    assert "multiple" in result.reason


def test_numeric_tcp_protocol_is_normalized_and_verified() -> None:
    result = verify(ec2_client=FakeEc2Client({None: response([rule(IpProtocol="6")])}))

    assert result.status == AwsVerificationStatus.VERIFIED
    assert result.finding is not None
    assert result.finding.rule.protocol == "tcp"
    assert result.finding.has_verified_provenance() is True


def test_invalid_tcp_port_range_fails_closed() -> None:
    with pytest.raises(AwsVerificationError, match="port range"):
        verify(
            ec2_client=FakeEc2Client(
                {None: response([rule(FromPort=1024, ToPort=22)])}
            )
        )


@pytest.mark.parametrize(
    "bad_rule",
    [
        rule(GroupId="sg-aaaaaaaaaaaaaaaaa"),
        rule(GroupOwnerId=EVENT_ACCOUNT),
        rule(SecurityGroupRuleId="not-a-rule-id"),
    ],
)
def test_live_rule_identity_mismatch_fails_closed(bad_rule: dict[str, Any]) -> None:
    with pytest.raises(AwsVerificationError):
        verify(ec2_client=FakeEc2Client({None: response([bad_rule])}))


def test_missing_aws_request_metadata_fails_closed() -> None:
    with pytest.raises(AwsVerificationError):
        verify(identity_client=FakeIdentityClient(request_id=None))
    with pytest.raises(AwsVerificationError):
        verify(ec2_client=FakeEc2Client({None: response([rule()], request_id=None)}))


def test_duplicate_rule_or_pagination_token_fails_closed() -> None:
    duplicate_pages = FakeEc2Client(
        {
            None: response([rule()], next_token="page-2"),
            "page-2": response([rule()], request_id="ec2-request-002"),
        }
    )
    with pytest.raises(AwsVerificationError, match="duplicate"):
        verify(ec2_client=duplicate_pages)

    repeated_token = FakeEc2Client(
        {
            None: response([], next_token="page-2"),
            "page-2": response([], request_id="ec2-request-002", next_token="page-2"),
        }
    )
    with pytest.raises(AwsVerificationError, match="pagination"):
        verify(ec2_client=repeated_token)


def test_page_limit_fails_closed() -> None:
    ec2 = FakeEc2Client({None: response([], next_token="page-2")})

    with pytest.raises(AwsVerificationError, match="page limit"):
        verify(ec2_client=ec2, verification_policy=policy(max_pages=1))


def test_provenance_tampering_invalidates_finding() -> None:
    result = verify()
    assert result.finding is not None
    trusted = result.finding
    tampered = SecurityFinding(
        alert_id=trusted.alert_id,
        provider=trusted.provider,
        account_id=trusted.account_id,
        region=trusted.region,
        resource_type=trusted.resource_type,
        resource_id=trusted.resource_id,
        rule=SecurityGroupRule(
            direction="ingress",
            protocol="tcp",
            from_port=20,
            to_port=22,
            source="0.0.0.0/0",
        ),
        provenance=trusted.provenance,
    )

    assert trusted.has_verified_provenance() is True
    assert tampered.has_verified_provenance() is False
    decision = plan_public_ssh_remediation(
        finding=tampered,
        terraform_resource=TerraformResourceRef(
            address="aws_security_group_rule.ssh_public",
            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
            file_path="security-groups.tf",
        ),
        replacement_source="10.20.30.40/32",
    )
    assert decision.decision == Decision.MANUAL_REVIEW
    assert decision.terraform_resource is None
