from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Ownership(str, Enum):
    TERRAFORM_STANDALONE_RULE = "terraform_standalone_rule"
    TERRAFORM_INLINE_RULE = "terraform_inline_rule"
    UNMANAGED_REMOTE_RULE = "unmanaged_remote_rule"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    AUTO_PR = "auto_pr"
    MANUAL_REVIEW = "manual_review"
    REJECT = "reject"


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


@dataclass(frozen=True)
class SecurityFinding:
    alert_id: str
    provider: str
    account_id: str
    region: str
    resource_type: str
    resource_id: str
    rule: SecurityGroupRule


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
    summary: str
    diff: str
