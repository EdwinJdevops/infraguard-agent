from __future__ import annotations

from pathlib import Path
import json
from typing import Any

import hcl2

from infraguard.models import Ownership, SecurityFinding, TerraformResourceRef


def classify_security_group_ownership(
    finding: SecurityFinding,
    terraform_root: Path,
    terraform_state_path: Path | None = None,
) -> TerraformResourceRef | None:
    state_resource_ids = _load_state_resource_ids(terraform_state_path)
    for file_path in sorted(terraform_root.rglob("*.tf")):
        parsed = _load_hcl(file_path)
        for resource in parsed.get("resource", []):
            for resource_type, resources in resource.items():
                for name, body in resources.items():
                    address = f"{resource_type}.{name}"
                    if resource_type == "aws_security_group_rule" and _standalone_rule_matches(body, finding):
                        return TerraformResourceRef(
                            address=address,
                            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
                            file_path=str(file_path),
                        )
                    if resource_type == "aws_vpc_security_group_ingress_rule" and _vpc_ingress_rule_matches(body, finding):
                        return TerraformResourceRef(
                            address=address,
                            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
                            file_path=str(file_path),
                        )
                    if (
                        resource_type == "aws_security_group"
                        and _inline_rule_matches(body, finding)
                        and state_resource_ids.get(address) == finding.resource_id
                    ):
                        return TerraformResourceRef(
                            address=address,
                            ownership=Ownership.TERRAFORM_INLINE_RULE,
                            file_path=str(file_path),
                        )
    return None


def _load_hcl(file_path: Path) -> dict[str, Any]:
    with file_path.open("r", encoding="utf-8") as handle:
        loaded = hcl2.load(handle)
    if not isinstance(loaded, dict):
        return {}
    return loaded


def _load_state_resource_ids(terraform_state_path: Path | None) -> dict[str, str]:
    if terraform_state_path is None or not terraform_state_path.exists():
        return {}

    with terraform_state_path.open("r", encoding="utf-8") as handle:
        state = json.load(handle)

    resource_ids: dict[str, str] = {}
    for resource in state.get("resources", []):
        mode = resource.get("mode")
        resource_type = resource.get("type")
        name = resource.get("name")
        if mode != "managed" or not resource_type or not name:
            continue
        address = f"{resource_type}.{name}"
        for instance in resource.get("instances", []):
            attributes = instance.get("attributes", {})
            resource_id = attributes.get("id")
            if isinstance(resource_id, str):
                resource_ids[address] = resource_id
    return resource_ids


def _standalone_rule_matches(body: dict[str, Any], finding: SecurityFinding) -> bool:
    return (
        body.get("type") == finding.rule.direction
        and _int_value(body.get("from_port")) == finding.rule.from_port
        and _int_value(body.get("to_port")) == finding.rule.to_port
        and str(body.get("protocol", "")).lower() == finding.rule.protocol.lower()
        and finding.rule.source in _list_value(body.get("cidr_blocks"))
        and _security_group_matches(body.get("security_group_id"), finding.resource_id)
    )


def _vpc_ingress_rule_matches(body: dict[str, Any], finding: SecurityFinding) -> bool:
    return (
        finding.rule.direction == "ingress"
        and _int_value(body.get("from_port")) == finding.rule.from_port
        and _int_value(body.get("to_port")) == finding.rule.to_port
        and str(body.get("ip_protocol", "")).lower() == finding.rule.protocol.lower()
        and body.get("cidr_ipv4") == finding.rule.source
        and _security_group_matches(body.get("security_group_id"), finding.resource_id)
    )


def _inline_rule_matches(body: dict[str, Any], finding: SecurityFinding) -> bool:
    for ingress in _list_value(body.get("ingress")):
        if not isinstance(ingress, dict):
            continue
        if (
            _int_value(ingress.get("from_port")) == finding.rule.from_port
            and _int_value(ingress.get("to_port")) == finding.rule.to_port
            and str(ingress.get("protocol", "")).lower() == finding.rule.protocol.lower()
            and finding.rule.source in _list_value(ingress.get("cidr_blocks"))
        ):
            return True
    return False


def _security_group_matches(value: Any, resource_id: str) -> bool:
    if value == resource_id:
        return True
    if isinstance(value, str) and value.startswith("${") and value.endswith(".id}"):
        return True
    return False


def _int_value(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _list_value(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
