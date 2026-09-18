from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from infraguard.models import (
    FindingProvenance,
    SecurityFinding,
    SecurityGroupRule,
    VerificationMethod,
    security_group_rule_fingerprint,
)

PUBLIC_SOURCES = {"0.0.0.0/0", "::/0"}
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
EVENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,127}$")
GROUP_ID_PATTERN = re.compile(r"^sg-[0-9a-f]{8,17}$")
RULE_ID_PATTERN = re.compile(r"^sgr-[0-9a-f]{8,17}$")
PRODUCT_ARN_PATTERN = re.compile(
    r"^arn:(?P<partition>aws(?:-us-gov|-cn)?):securityhub:"
    r"(?P<region>[a-z0-9-]+)::product/aws/securityhub$"
)
GROUP_ARN_PATTERN = re.compile(
    r"^arn:(?P<partition>aws(?:-us-gov|-cn)?):ec2:(?P<region>[a-z0-9-]+):"
    r"(?P<account>\d{12}):security-group/(?P<group>sg-[0-9a-f]{8,17})$"
)


class IdentityClient(Protocol):
    def get_caller_identity(self) -> dict[str, Any]: ...


class Ec2Client(Protocol):
    def describe_security_group_rules(self, **kwargs: Any) -> dict[str, Any]: ...


class AwsVerificationStatus(StrEnum):
    VERIFIED = "verified"
    RESOLVED = "resolved"
    MANUAL_REVIEW = "manual_review"
    REJECTED = "rejected"


class AwsVerificationError(RuntimeError):
    """Raised when AWS evidence cannot be read or is structurally unsafe to consume."""


@dataclass(frozen=True)
class AwsVerificationPolicy:
    allowed_event_accounts: frozenset[str]
    max_event_age: timedelta
    max_future_skew: timedelta
    max_pages: int

    def __post_init__(self) -> None:
        if not self.allowed_event_accounts or any(
            not ACCOUNT_ID_PATTERN.fullmatch(account)
            for account in self.allowed_event_accounts
        ):
            raise ValueError("allowed_event_accounts must contain valid AWS account IDs")
        if self.max_event_age <= timedelta(0):
            raise ValueError("max_event_age must be positive")
        if self.max_future_skew < timedelta(0):
            raise ValueError("max_future_skew cannot be negative")
        if self.max_pages < 1:
            raise ValueError("max_pages must be positive")


@dataclass(frozen=True)
class AwsVerificationResult:
    status: AwsVerificationStatus
    reason: str
    finding: SecurityFinding | None = None
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status == AwsVerificationStatus.VERIFIED:
            if self.finding is None or not self.finding.has_verified_provenance():
                raise ValueError("verified result requires a provenance-bound finding")
        elif self.finding is not None:
            raise ValueError("non-verified result cannot contain an automation finding")


@dataclass(frozen=True)
class _EventContext:
    event_id: str
    source_account_id: str
    event_time: datetime
    finding_id: str
    product_arn: str
    target_account_id: str
    region: str
    resource_id: str
    observed_at: datetime


def verify_security_hub_cspm_event(
    event: dict[str, Any],
    *,
    identity_client: IdentityClient,
    ec2_client: Ec2Client,
    ec2_region: str,
    policy: AwsVerificationPolicy,
    now: datetime,
) -> AwsVerificationResult:
    """Bind one EC2.13 ASFF event to one current EC2 security-group rule.

    The clients must use credentials for the target account. Production composition is
    responsible for assuming an allowlisted read-only role before calling this function.
    """

    verified_now = _aware_utc(now, "now")
    try:
        context = _parse_event(event)
    except AwsVerificationError as exc:
        return _rejected(str(exc), "security_hub_event_rejected")
    if context.source_account_id not in policy.allowed_event_accounts:
        return _rejected("event source account is not allowlisted", "event_account_rejected")
    if context.event_time > verified_now + policy.max_future_skew:
        return _rejected("event timestamp exceeds allowed future skew", "future_event_rejected")
    if context.observed_at > verified_now + policy.max_future_skew:
        return _rejected(
            "finding observation timestamp exceeds allowed future skew",
            "future_finding_rejected",
        )
    if verified_now - context.event_time > policy.max_event_age:
        return _rejected("event exceeds configured maximum age", "stale_event_rejected")
    if verified_now - context.observed_at > policy.max_event_age:
        return _rejected("finding exceeds configured maximum age", "stale_finding_rejected")
    if context.observed_at > context.event_time + policy.max_future_skew:
        return _rejected(
            "finding observation timestamp is inconsistent with event time",
            "finding_event_time_mismatch",
        )
    if ec2_region != context.region:
        return _rejected("EC2 client region does not match finding region", "region_mismatch")

    identity, identity_request_id = _call_identity(identity_client)
    if identity != context.target_account_id:
        return _rejected(
            "assumed AWS identity does not match finding account",
            "verifier_account_mismatch",
        )

    rules, request_ids = _load_rules(
        ec2_client,
        group_id=context.resource_id,
        max_pages=policy.max_pages,
    )
    supported: list[dict[str, Any]] = []
    broad: list[dict[str, Any]] = []
    rule_ids: set[str] = set()
    for rule in rules:
        rule_id = _validate_rule_binding(rule, context)
        if rule_id in rule_ids:
            raise AwsVerificationError("EC2 returned a duplicate security-group rule")
        rule_ids.add(rule_id)
        source = _public_source(rule)
        if source is None or rule.get("IsEgress") is not False:
            continue
        protocol = str(rule.get("IpProtocol", "")).lower()
        if protocol == "-1":
            broad.append(rule)
            continue
        if protocol not in {"tcp", "6"}:
            continue
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if not isinstance(from_port, int) or not isinstance(to_port, int):
            raise AwsVerificationError("EC2 returned invalid TCP port evidence")
        if not 0 <= from_port <= to_port <= 65535:
            raise AwsVerificationError("EC2 returned an invalid TCP port range")
        if from_port <= 22 <= to_port:
            supported.append(rule)

    if broad:
        return AwsVerificationResult(
            status=AwsVerificationStatus.MANUAL_REVIEW,
            reason=(
                "live public all-protocol ingress exposes SSH but automatic patching "
                "is unsupported"
            ),
            evidence=("aws_identity_verified", "public_all_protocol_rule_detected"),
        )
    if not supported:
        return AwsVerificationResult(
            status=AwsVerificationStatus.RESOLVED,
            reason="independent EC2 lookup found no current public TCP rule exposing port 22",
            evidence=("aws_identity_verified", "live_public_ssh_absent"),
        )
    if len(supported) != 1:
        return AwsVerificationResult(
            status=AwsVerificationStatus.MANUAL_REVIEW,
            reason="multiple live public SSH rules match the security-group finding",
            evidence=("aws_identity_verified", "multiple_public_ssh_rules"),
        )

    live_rule = supported[0]
    source = _public_source(live_rule)
    if source is None:
        raise AwsVerificationError("verified rule lost its public source")
    rule_id = _required_text(live_rule, "SecurityGroupRuleId", RULE_ID_PATTERN)
    normalized_rule = SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=int(live_rule["FromPort"]),
        to_port=int(live_rule["ToPort"]),
        source=source,
    )
    finding = SecurityFinding(
        alert_id=context.finding_id,
        provider="aws",
        account_id=context.target_account_id,
        region=context.region,
        resource_type="aws_security_group",
        resource_id=context.resource_id,
        rule=normalized_rule,
        provenance=FindingProvenance(
            method=VerificationMethod.AWS_EC2_DESCRIBE_SECURITY_GROUP_RULES,
            transport_event_id=context.event_id,
            security_hub_finding_id=context.finding_id,
            product_arn=context.product_arn,
            source_account_id=context.source_account_id,
            verifier_account_id=identity,
            region=context.region,
            resource_id=context.resource_id,
            security_group_rule_id=rule_id,
            observed_at=context.observed_at,
            verified_at=verified_now,
            aws_request_ids=(identity_request_id, *request_ids),
            rule_fingerprint=security_group_rule_fingerprint(
                account_id=context.target_account_id,
                resource_id=context.resource_id,
                security_group_rule_id=rule_id,
                rule=normalized_rule,
            ),
        ),
    )
    return AwsVerificationResult(
        status=AwsVerificationStatus.VERIFIED,
        reason="Security Hub metadata is bound to one current EC2 public SSH rule",
        finding=finding,
        evidence=(
            "security_hub_cspm_event_validated",
            "aws_identity_verified",
            "live_public_ssh_rule_verified",
        ),
    )


def _parse_event(event: dict[str, Any]) -> _EventContext:
    if not isinstance(event, dict):
        raise AwsVerificationError("Security Hub event must be an object")
    if event.get("version") != "0":
        raise AwsVerificationError("unsupported EventBridge event version")
    if event.get("source") != "aws.securityhub":
        raise AwsVerificationError("event source is not AWS Security Hub")
    if event.get("detail-type") != "Security Hub Findings - Imported":
        raise AwsVerificationError("unsupported Security Hub event type")
    event_id = _required_text(event, "id", EVENT_ID_PATTERN)
    source_account_id = _required_text(event, "account", ACCOUNT_ID_PATTERN)
    event_time = _parse_timestamp(event.get("time"), "event time")

    detail = event.get("detail")
    if not isinstance(detail, dict):
        raise AwsVerificationError("Security Hub event detail must be an object")
    findings = detail.get("findings")
    if not isinstance(findings, list) or len(findings) != 1 or not isinstance(findings[0], dict):
        raise AwsVerificationError("Security Hub event must contain exactly one ASFF finding")
    finding = findings[0]
    if finding.get("SchemaVersion") != "2018-10-08":
        raise AwsVerificationError("unsupported ASFF schema version")
    if finding.get("RecordState") != "ACTIVE":
        raise AwsVerificationError("Security Hub finding is not active")
    workflow = finding.get("Workflow")
    if not isinstance(workflow, dict) or workflow.get("Status") not in {"NEW", "NOTIFIED"}:
        raise AwsVerificationError("Security Hub finding workflow is not actionable")
    compliance = finding.get("Compliance")
    if not isinstance(compliance, dict):
        raise AwsVerificationError("Security Hub finding has no compliance evidence")
    if compliance.get("SecurityControlId") != "EC2.13":
        raise AwsVerificationError("finding is not consolidated Security Hub control EC2.13")
    if compliance.get("Status") != "FAILED":
        raise AwsVerificationError("Security Hub control is not failed")

    finding_id = _required_text(finding, "Id")
    product_arn = _required_text(finding, "ProductArn")
    product_match = PRODUCT_ARN_PATTERN.fullmatch(product_arn)
    if product_match is None:
        raise AwsVerificationError("finding product is not AWS Security Hub CSPM")
    target_account_id = _required_text(finding, "AwsAccountId", ACCOUNT_ID_PATTERN)
    region = _required_text(finding, "Region")
    if product_match.group("region") != region:
        raise AwsVerificationError("finding region does not match product ARN")
    observed_at = _parse_timestamp(finding.get("UpdatedAt"), "finding UpdatedAt")

    resources = finding.get("Resources")
    if not isinstance(resources, list) or len(resources) != 1:
        raise AwsVerificationError("finding must identify exactly one EC2 security group")
    resource = resources[0]
    if not isinstance(resource, dict) or resource.get("Type") != "AwsEc2SecurityGroup":
        raise AwsVerificationError("finding resource is not an EC2 security group")
    if resource.get("Region") != region:
        raise AwsVerificationError("security-group resource region mismatch")
    if resource.get("Partition") != product_match.group("partition"):
        raise AwsVerificationError("security-group resource partition mismatch")
    group_arn = _required_text(resource, "Id")
    group_match = GROUP_ARN_PATTERN.fullmatch(group_arn)
    if group_match is None:
        raise AwsVerificationError("security-group resource ID is not an EC2 ARN")
    if (
        group_match.group("partition") != product_match.group("partition")
        or group_match.group("region") != region
        or group_match.group("account") != target_account_id
    ):
        raise AwsVerificationError("security-group ARN does not match finding identity")
    resource_id = group_match.group("group")
    details = resource.get("Details")
    sg_details = details.get("AwsEc2SecurityGroup") if isinstance(details, dict) else None
    if not isinstance(sg_details, dict) or sg_details.get("GroupId") != resource_id:
        raise AwsVerificationError("security-group details do not match resource ARN")

    return _EventContext(
        event_id=event_id,
        source_account_id=source_account_id,
        event_time=event_time,
        finding_id=finding_id,
        product_arn=product_arn,
        target_account_id=target_account_id,
        region=region,
        resource_id=resource_id,
        observed_at=observed_at,
    )


def _call_identity(client: IdentityClient) -> tuple[str, str]:
    try:
        response = client.get_caller_identity()
    except Exception as exc:
        raise AwsVerificationError("AWS identity lookup failed") from exc
    if not isinstance(response, dict):
        raise AwsVerificationError("AWS identity response is invalid")
    account_id = _required_text(response, "Account", ACCOUNT_ID_PATTERN)
    request_metadata = response.get("ResponseMetadata")
    if not isinstance(request_metadata, dict):
        raise AwsVerificationError("AWS identity response has no request metadata")
    request_id = _required_text(request_metadata, "RequestId")
    return account_id, request_id


def _load_rules(
    client: Ec2Client,
    *,
    group_id: str,
    max_pages: int,
) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    rules: list[dict[str, Any]] = []
    request_ids: list[str] = []
    token: str | None = None
    seen_tokens: set[str] = set()
    for _ in range(max_pages):
        parameters: dict[str, Any] = {
            "Filters": [{"Name": "group-id", "Values": [group_id]}],
            "MaxResults": 1000,
        }
        if token:
            parameters["NextToken"] = token
        try:
            response = client.describe_security_group_rules(**parameters)
        except Exception as exc:
            raise AwsVerificationError("EC2 security-group rule lookup failed") from exc
        if not isinstance(response, dict) or not isinstance(
            response.get("SecurityGroupRules"), list
        ):
            raise AwsVerificationError("EC2 rule response is invalid")
        request_metadata = response.get("ResponseMetadata")
        if not isinstance(request_metadata, dict):
            raise AwsVerificationError("EC2 rule response has no request metadata")
        request_ids.append(_required_text(request_metadata, "RequestId"))
        page_rules = response["SecurityGroupRules"]
        if any(not isinstance(rule, dict) for rule in page_rules):
            raise AwsVerificationError("EC2 rule response contains an invalid rule")
        rules.extend(page_rules)
        next_token = response.get("NextToken")
        if next_token is None:
            return rules, tuple(request_ids)
        if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
            raise AwsVerificationError("EC2 pagination token is invalid or repeated")
        seen_tokens.add(next_token)
        token = next_token
    raise AwsVerificationError("EC2 rule response exceeded the configured page limit")


def _public_source(rule: dict[str, Any]) -> str | None:
    sources = [source for source in (rule.get("CidrIpv4"), rule.get("CidrIpv6")) if source]
    if len(sources) > 1:
        raise AwsVerificationError("EC2 rule contains multiple CIDR source fields")
    if not sources:
        return None
    source = sources[0]
    if not isinstance(source, str):
        raise AwsVerificationError("EC2 rule CIDR source is invalid")
    return source if source in PUBLIC_SOURCES else None


def _validate_rule_binding(rule: dict[str, Any], context: _EventContext) -> str:
    if rule.get("GroupId") != context.resource_id:
        raise AwsVerificationError("EC2 rule does not match requested security group")
    if rule.get("GroupOwnerId") != context.target_account_id:
        raise AwsVerificationError("EC2 rule owner does not match finding account")
    return _required_text(rule, "SecurityGroupRuleId", RULE_ID_PATTERN)


def _required_text(
    value: dict[str, Any],
    key: str,
    pattern: re.Pattern[str] | None = None,
) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result or len(result) > 2048:
        raise AwsVerificationError(f"required field {key} is invalid")
    if pattern is not None and pattern.fullmatch(result) is None:
        raise AwsVerificationError(f"required field {key} has an invalid format")
    return result


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise AwsVerificationError(f"{field} must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AwsVerificationError(f"{field} must be an ISO 8601 timestamp") from exc
    return _aware_utc(parsed, field)


def _aware_utc(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AwsVerificationError(f"{field} must include a timezone")
    return value.astimezone(UTC)


def _rejected(reason: str, evidence: str) -> AwsVerificationResult:
    return AwsVerificationResult(
        status=AwsVerificationStatus.REJECTED,
        reason=reason,
        evidence=(evidence,),
    )
