from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from infraguard.models import SecurityFinding, SecurityGroupRule


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SecurityGroupRuleInput(StrictModel):
    direction: Literal["ingress"]
    protocol: Literal["tcp"]
    from_port: int = Field(ge=0, le=65535)
    to_port: int = Field(ge=0, le=65535)
    source: Literal["0.0.0.0/0", "::/0"]


class RemediationPlanRequest(StrictModel):
    alert_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    provider: Literal["aws"] = "aws"
    account_id: str = Field(pattern=r"^\d{12}$")
    region: str = Field(pattern=r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
    resource_type: Literal["aws_security_group"] = "aws_security_group"
    resource_id: str = Field(pattern=r"^sg-[0-9a-f]{8,17}$")
    rule: SecurityGroupRuleInput
    replacement_source: str | None = Field(default=None, min_length=3, max_length=64)

    def to_finding(self) -> SecurityFinding:
        return SecurityFinding(
            alert_id=self.alert_id,
            provider=self.provider,
            account_id=self.account_id,
            region=self.region,
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            rule=SecurityGroupRule(**self.rule.model_dump()),
        )


class TerraformResourceResponse(StrictModel):
    address: str
    file_path: str


class PatchResponse(StrictModel):
    file_path: str
    resource_address: str
    summary: str
    diff: str


class ValidationResponse(StrictModel):
    passed: bool
    checks: dict[str, bool]
    errors: list[str]


class RemediationPlanResponse(StrictModel):
    alert_id: str
    decision: Literal["auto_pr", "manual_review", "reject"]
    reason: str
    ownership: Literal[
        "terraform_standalone_rule",
        "terraform_inline_rule",
        "unmanaged_remote_rule",
        "unknown",
    ]
    can_open_pr: bool
    decision_evidence: list[str]
    terraform_resource: TerraformResourceResponse | None
    patch: PatchResponse | None
    validation: ValidationResponse | None
    evidence_bundle: dict[str, object] | None
    pr_body: str | None
    publication: Literal["not_attempted"] = "not_attempted"
