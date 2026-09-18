from datetime import UTC, datetime

from infraguard.models import (
    FindingProvenance,
    SecurityGroupRule,
    VerificationMethod,
    security_group_rule_fingerprint,
)


def verified_provenance(
    *,
    source: str = "0.0.0.0/0",
    rule_id: str = "sgr-1234567890abcdef0",
    finding_id: str = "alert-001",
    protocol: str = "tcp",
    from_port: int = 22,
    to_port: int = 22,
) -> FindingProvenance:
    observed_at = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    rule = SecurityGroupRule(
        direction="ingress",
        protocol=protocol,
        from_port=from_port,
        to_port=to_port,
        source=source,
    )
    return FindingProvenance(
        method=VerificationMethod.AWS_EC2_DESCRIBE_SECURITY_GROUP_RULES,
        transport_event_id="11111111-2222-3333-4444-555555555555",
        security_hub_finding_id=finding_id,
        product_arn="arn:aws:securityhub:us-east-1::product/aws/securityhub",
        source_account_id="210987654321",
        verifier_account_id="123456789012",
        region="us-east-1",
        resource_id="sg-1234567890abcdef0",
        security_group_rule_id=rule_id,
        observed_at=observed_at,
        verified_at=observed_at,
        aws_request_ids=("sts-request-001", "ec2-request-001"),
        rule_fingerprint=security_group_rule_fingerprint(
            account_id="123456789012",
            resource_id="sg-1234567890abcdef0",
            security_group_rule_id=rule_id,
            rule=rule,
        ),
    )
