from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class Ownership(StrEnum):
    TERRAFORM_STANDALONE_RULE = "terraform_standalone_rule"
    TERRAFORM_INLINE_RULE = "terraform_inline_rule"
    UNMANAGED_REMOTE_RULE = "unmanaged_remote_rule"
    UNKNOWN = "unknown"


class Decision(StrEnum):
    AUTO_PR = "auto_pr"
    MANUAL_REVIEW = "manual_review"
    REJECT = "reject"


class VerificationMethod(StrEnum):
    AWS_EC2_DESCRIBE_SECURITY_GROUP_RULES = "aws_ec2_describe_security_group_rules"


@dataclass(frozen=True)
class SecurityGroupRule:
    direction: str
    protocol: str
    from_port: int
    to_port: int
    source: str

    def is_public_ssh(self) -> bool:
        return (
            self.direction == "ingress"
            and self.protocol.lower() == "tcp"
            and self.from_port <= 22 <= self.to_port
            and self.source in {"0.0.0.0/0", "::/0"}
        )


def security_group_rule_fingerprint(
    *,
    account_id: str,
    resource_id: str,
    security_group_rule_id: str,
    rule: SecurityGroupRule,
) -> str:
    """Return a stable digest binding a normalized rule to its AWS identity."""

    normalized = {
        "account_id": account_id,
        "direction": rule.direction,
        "from_port": rule.from_port,
        "protocol": rule.protocol.lower(),
        "resource_id": resource_id,
        "security_group_rule_id": security_group_rule_id,
        "source": rule.source,
        "to_port": rule.to_port,
    }
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class FindingProvenance:
    method: VerificationMethod
    transport_event_id: str
    security_hub_finding_id: str
    product_arn: str
    source_account_id: str
    verifier_account_id: str
    region: str
    resource_id: str
    security_group_rule_id: str
    observed_at: datetime
    verified_at: datetime
    aws_request_ids: tuple[str, ...]
    rule_fingerprint: str


@dataclass(frozen=True)
class SecurityFinding:
    alert_id: str
    provider: str
    account_id: str
    region: str
    resource_type: str
    resource_id: str
    rule: SecurityGroupRule
    provenance: FindingProvenance | None = None

    def has_verified_provenance(self) -> bool:
        provenance = self.provenance
        expected_product_arn = re.compile(
            rf"^arn:aws(?:-us-gov|-cn)?:securityhub:{re.escape(self.region)}::"
            r"product/aws/securityhub$"
        )
        return bool(
            provenance
            and self.provider == "aws"
            and self.resource_type == "aws_security_group"
            and provenance.method
            == VerificationMethod.AWS_EC2_DESCRIBE_SECURITY_GROUP_RULES
            and provenance.transport_event_id
            and provenance.security_hub_finding_id == self.alert_id
            and expected_product_arn.fullmatch(provenance.product_arn)
            and len(provenance.source_account_id) == 12
            and provenance.source_account_id.isdigit()
            and provenance.verifier_account_id == self.account_id
            and provenance.region == self.region
            and provenance.resource_id == self.resource_id
            and re.fullmatch(
                r"sgr-[0-9a-f]{8,17}", provenance.security_group_rule_id
            )
            and provenance.aws_request_ids
            and all(provenance.aws_request_ids)
            and provenance.observed_at.tzinfo is not None
            and provenance.observed_at.utcoffset() is not None
            and provenance.verified_at.tzinfo is not None
            and provenance.verified_at.utcoffset() is not None
            and provenance.verified_at >= provenance.observed_at
            and provenance.rule_fingerprint
            and re.fullmatch(r"[0-9a-f]{64}", provenance.rule_fingerprint) is not None
            and provenance.rule_fingerprint
            == security_group_rule_fingerprint(
                account_id=self.account_id,
                resource_id=self.resource_id,
                security_group_rule_id=provenance.security_group_rule_id,
                rule=self.rule,
            )
        )


@dataclass(frozen=True)
class TerraformResourceRef:
    address: str
    ownership: Ownership
    file_path: str | None = None


@dataclass(frozen=True)
class RemediationDecision:
    decision: Decision
    reason: str
    finding: SecurityFinding
    ownership: Ownership
    replacement_source: str | None
    evidence: list[str] = field(default_factory=list)
    terraform_resource: TerraformResourceRef | None = None

    @property
    def can_open_pr(self) -> bool:
        return self.decision == Decision.AUTO_PR


@dataclass(frozen=True)
class TerraformPatch:
    file_path: str
    before: str
    after: str
    resource_address: str
    source_before: str
    replacement_source: str
    summary: str
    diff: str


@dataclass(frozen=True)
class PatchValidation:
    passed: bool
    checks: dict[str, bool]
    errors: list[str] = field(default_factory=list)

    def to_evidence(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "checks": self.checks,
            "errors": self.errors,
        }


@dataclass(frozen=True)
class RemediationRun:
    decision: RemediationDecision
    patch: TerraformPatch | None
    validation: PatchValidation | None
    evidence_json: dict[str, object] | None
    pr_markdown: str | None

    @property
    def can_open_pr(self) -> bool:
        return (
            self.decision.decision == Decision.AUTO_PR
            and self.patch is not None
            and self.validation is not None
            and self.validation.passed
            and self.evidence_json is not None
            and self.pr_markdown is not None
        )
