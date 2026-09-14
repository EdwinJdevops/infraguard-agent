from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import hcl2

from infraguard.models import Ownership, SecurityFinding, TerraformResourceRef


class OwnershipError(ValueError):
    """Raised when Terraform evidence cannot establish one unambiguous owner."""


def classify_security_group_ownership(
    finding: SecurityFinding,
    terraform_root: Path,
    terraform_state_path: Path | None = None,
) -> TerraformResourceRef | None:
    state_attributes = _load_state_resource_attributes(terraform_state_path)
    matches: list[TerraformResourceRef] = []
    trusted_root = terraform_root.resolve()
    for discovered_path in sorted(trusted_root.rglob("*.tf")):
        file_path = _trusted_terraform_file(discovered_path, trusted_root)
        try:
            parsed = _load_hcl(file_path)
        except Exception as exc:
            raise OwnershipError(f"failed to parse Terraform file {file_path}: {exc}") from exc
        for resource in parsed.get("resource", []):
            for resource_type, resources in resource.items():
                for name, body in resources.items():
                    address = f"{resource_type}.{name}"
                    if resource_type == "aws_security_group_rule" and _standalone_rule_matches(
                        body, finding, address, state_attributes
                    ):
                        matches.append(TerraformResourceRef(
                            address=address,
                            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
                            file_path=str(file_path),
                        ))
                    if (
                        resource_type == "aws_vpc_security_group_ingress_rule"
                        and _vpc_ingress_rule_matches(body, finding, address, state_attributes)
                    ):
                        matches.append(TerraformResourceRef(
                            address=address,
                            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
                            file_path=str(file_path),
                        ))
                    if (
                        resource_type == "aws_security_group"
                        and _inline_rule_matches(body, finding)
                        and _state_has_attribute(
                            state_attributes,
                            address,
                            "id",
                            finding.resource_id,
                        )
                    ):
                        matches.append(TerraformResourceRef(
                            address=address,
                            ownership=Ownership.TERRAFORM_INLINE_RULE,
                            file_path=str(file_path),
                        ))
    if len(matches) > 1:
        addresses = ", ".join(match.address for match in matches)
        raise OwnershipError(f"multiple Terraform resources match finding: {addresses}")
    return matches[0] if matches else None


def _trusted_terraform_file(file_path: Path, trusted_root: Path) -> Path:
    if file_path.is_symlink():
        raise OwnershipError("Terraform source symlinks are not supported")
    try:
        resolved = file_path.resolve(strict=True)
        resolved.relative_to(trusted_root)
    except (OSError, ValueError) as exc:
        raise OwnershipError("Terraform source resolves outside the configured root") from exc
    if not resolved.is_file():
        raise OwnershipError("Terraform source path is not a regular file")
    return resolved


def _load_hcl(file_path: Path) -> dict[str, Any]:
    with file_path.open("r", encoding="utf-8") as handle:
        loaded = hcl2.load(handle)
    if not isinstance(loaded, dict):
        return {}
    return loaded


def _load_state_resource_attributes(
    terraform_state_path: Path | None,
) -> dict[str, list[dict[str, Any]]]:
    if terraform_state_path is None or not terraform_state_path.exists():
        return {}

    try:
        with terraform_state_path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise OwnershipError(f"failed to parse Terraform state: {exc}") from exc
    if not isinstance(state, dict) or not isinstance(state.get("resources", []), list):
        raise OwnershipError("failed to parse Terraform state: invalid state structure")

    resource_attributes: dict[str, list[dict[str, Any]]] = {}
    for resource in state.get("resources", []):
        mode = resource.get("mode")
        resource_type = resource.get("type")
        name = resource.get("name")
        if mode != "managed" or not resource_type or not name:
            continue
        module = resource.get("module")
        address = f"{module}.{resource_type}.{name}" if module else f"{resource_type}.{name}"
        for instance in resource.get("instances", []):
            attributes = instance.get("attributes", {})
            if isinstance(attributes, dict):
                resource_attributes.setdefault(address, []).append(attributes)
    return resource_attributes


def _standalone_rule_matches(
    body: dict[str, Any],
    finding: SecurityFinding,
    address: str,
    state_attributes: dict[str, list[dict[str, Any]]],
) -> bool:
    return (
        body.get("type") == finding.rule.direction
        and _int_value(body.get("from_port")) == finding.rule.from_port
        and _int_value(body.get("to_port")) == finding.rule.to_port
        and _protocol_matches(body.get("protocol"), finding.rule.protocol)
        and finding.rule.source
        in _list_value(
            body.get(
                "ipv6_cidr_blocks" if finding.rule.source == "::/0" else "cidr_blocks"
            )
        )
        and _security_group_matches(
            body.get("security_group_id"), finding.resource_id, address, state_attributes
        )
    )


def _vpc_ingress_rule_matches(
    body: dict[str, Any],
    finding: SecurityFinding,
    address: str,
    state_attributes: dict[str, list[dict[str, Any]]],
) -> bool:
    return (
        finding.rule.direction == "ingress"
        and _int_value(body.get("from_port")) == finding.rule.from_port
        and _int_value(body.get("to_port")) == finding.rule.to_port
        and _protocol_matches(body.get("ip_protocol"), finding.rule.protocol)
        and body.get("cidr_ipv6" if finding.rule.source == "::/0" else "cidr_ipv4")
        == finding.rule.source
        and _security_group_matches(
            body.get("security_group_id"), finding.resource_id, address, state_attributes
        )
    )


def _inline_rule_matches(body: dict[str, Any], finding: SecurityFinding) -> bool:
    for ingress in _list_value(body.get("ingress")):
        if not isinstance(ingress, dict):
            continue
        if (
            _int_value(ingress.get("from_port")) == finding.rule.from_port
            and _int_value(ingress.get("to_port")) == finding.rule.to_port
            and _protocol_matches(ingress.get("protocol"), finding.rule.protocol)
            and finding.rule.source in _list_value(ingress.get("cidr_blocks"))
        ):
            return True
    return False


def _security_group_matches(
    value: Any,
    resource_id: str,
    rule_address: str,
    state_attributes: dict[str, list[dict[str, Any]]],
) -> bool:
    if value == resource_id:
        return True
    if _state_has_attribute(state_attributes, rule_address, "security_group_id", resource_id):
        return True
    if isinstance(value, str):
        match = re.fullmatch(r"\$\{(aws_security_group\.[^.]+)\.id}", value)
        if match and _state_has_attribute(state_attributes, match.group(1), "id", resource_id):
            return True
    return False


def _state_has_attribute(
    state_attributes: dict[str, list[dict[str, Any]]],
    address: str,
    attribute: str,
    expected: str,
) -> bool:
    return any(values.get(attribute) == expected for values in state_attributes.get(address, []))


def _int_value(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _protocol_matches(value: Any, expected: str) -> bool:
    normalized = str(value).lower()
    if expected.lower() == "tcp":
        return normalized in {"tcp", "6"}
    return normalized == expected.lower()


def _list_value(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
