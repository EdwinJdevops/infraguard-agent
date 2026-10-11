from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import hcl2

from infraguard.models import (
    Ownership,
    OwnershipProof,
    SecurityFinding,
    TerraformResourceRef,
)


class OwnershipError(ValueError):
    """Raised when Terraform evidence cannot establish one unambiguous owner."""


@dataclass(frozen=True)
class _TerraformState:
    resources: dict[str, list[dict[str, Any]]]
    lineage: str
    serial: int


def classify_security_group_ownership(
    finding: SecurityFinding,
    terraform_root: Path,
    terraform_state_path: Path | None = None,
) -> TerraformResourceRef | None:
    state = _load_state(terraform_state_path)
    matches: list[TerraformResourceRef] = []
    trusted_root = terraform_root.resolve()
    if not trusted_root.is_dir():
        raise OwnershipError("Terraform root is not a directory")
    for path in trusted_root.iterdir():
        if (
            path.name.endswith(".tf.json")
            or path.name == "override.tf"
            or path.name.endswith("_override.tf")
        ):
            raise OwnershipError("unsupported Terraform configuration: JSON or override files")
    for discovered_path in sorted(trusted_root.glob("*.tf")):
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
                        resource_type, body, finding, address, state
                    ):
                        matches.append(TerraformResourceRef(
                            address=address,
                            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
                            file_path=str(file_path),
                            ownership_proof=OwnershipProof.TERRAFORM_STATE_RULE_ID,
                            state_rule_id=finding.provenance.security_group_rule_id,
                            state_lineage=state.lineage,
                            state_serial=state.serial,
                        ))
                    if (
                        resource_type == "aws_vpc_security_group_ingress_rule"
                        and _standalone_rule_matches(
                            resource_type, body, finding, address, state
                        )
                    ):
                        matches.append(TerraformResourceRef(
                            address=address,
                            ownership=Ownership.TERRAFORM_STANDALONE_RULE,
                            file_path=str(file_path),
                            ownership_proof=OwnershipProof.TERRAFORM_STATE_RULE_ID,
                            state_rule_id=finding.provenance.security_group_rule_id,
                            state_lineage=state.lineage,
                            state_serial=state.serial,
                        ))
                    if (
                        resource_type == "aws_security_group"
                        and _inline_rule_matches(body, finding)
                        and _state_has_attribute(
                            state.resources if state else {},
                            address,
                            "id",
                            finding.resource_id,
                        )
                    ):
                        matches.append(TerraformResourceRef(
                            address=address,
                            ownership=Ownership.TERRAFORM_INLINE_RULE,
                            file_path=str(file_path),
                            ownership_proof=(
                                OwnershipProof.TERRAFORM_STATE_PARENT_SECURITY_GROUP_ID
                            ),
                            state_lineage=state.lineage,
                            state_serial=state.serial,
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


def _load_state(terraform_state_path: Path | None) -> _TerraformState | None:
    if terraform_state_path is None:
        return None
    if not terraform_state_path.exists():
        raise OwnershipError("Terraform state path does not exist")

    try:
        with terraform_state_path.open("r", encoding="utf-8") as handle:
            state = json.load(handle, object_pairs_hook=_unique_json_object)
    except (OSError, ValueError) as exc:
        raise OwnershipError(f"failed to parse Terraform state: {exc}") from exc
    if (
        not isinstance(state, dict)
        or type(state.get("version")) is not int
        or state["version"] != 4
        or not isinstance(state.get("resources"), list)
    ):
        raise OwnershipError("failed to parse Terraform state: invalid state structure")
    lineage = state.get("lineage")
    serial = state.get("serial")
    if not isinstance(lineage, str) or not lineage.strip() or type(serial) is not int or serial < 0:
        raise OwnershipError(
            "failed to parse Terraform state: lineage and non-negative serial are required"
        )

    resource_attributes: dict[str, list[dict[str, Any]]] = {}
    seen_addresses: set[str] = set()
    for resource in state.get("resources", []):
        if not isinstance(resource, dict):
            raise OwnershipError("invalid Terraform state resource")
        mode = resource.get("mode")
        resource_type = resource.get("type")
        name = resource.get("name")
        if mode not in ("managed", "data") or not all(
            isinstance(value, str) and value for value in (resource_type, name)
        ):
            raise OwnershipError("invalid Terraform state resource identity")
        if mode != "managed":
            continue
        module = resource.get("module")
        if module is not None and not isinstance(module, str):
            raise OwnershipError("invalid Terraform state module address")
        address = f"{module}.{resource_type}.{name}" if module else f"{resource_type}.{name}"
        if address in seen_addresses:
            raise OwnershipError("duplicate managed resource address in Terraform state")
        seen_addresses.add(address)
        instances = resource.get("instances")
        if not isinstance(instances, list):
            raise OwnershipError("invalid Terraform state instances")
        supported = resource.get("provider") == 'provider["registry.terraform.io/hashicorp/aws"]'
        attributes_list = []
        for instance in instances:
            if not isinstance(instance, dict) or not isinstance(instance.get("attributes"), dict):
                raise OwnershipError("invalid Terraform state instance attributes")
            if (
                "index_key" in instance
                or "deposed" in instance
                or instance.get("status") not in (None, "ready")
            ):
                supported = False
            attributes_list.append(instance["attributes"])
        if supported:
            resource_attributes[address] = attributes_list
    return _TerraformState(resources=resource_attributes, lineage=lineage, serial=serial)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OwnershipError("duplicate key in Terraform state JSON")
        result[key] = value
    return result


def _standalone_rule_matches(
    resource_type: str,
    body: dict[str, Any],
    finding: SecurityFinding,
    address: str,
    state: _TerraformState | None,
) -> bool:
    provenance = finding.provenance
    if (
        state is None
        or not finding.has_verified_provenance()
        or provenance is None
        or "count" in body
        or "for_each" in body
        or any(key in body for key in ("provider", "lifecycle", "provisioner", "connection"))
        or body.get("security_group_id") != finding.resource_id
    ):
        return False
    instances = state.resources.get(address, [])
    if len(instances) != 1:
        return False
    attributes = instances[0]
    if resource_type == "aws_security_group_rule":
        source_attribute = (
            "ipv6_cidr_blocks" if finding.rule.source == "::/0" else "cidr_blocks"
        )
        source_matches = _single_source_matches(
            body.get(source_attribute), finding.rule.source
        ) and _single_source_matches(attributes.get(source_attribute), finding.rule.source)
        other_sources = (
            "cidr_blocks" if source_attribute == "ipv6_cidr_blocks" else "ipv6_cidr_blocks",
            "source_security_group_id",
            "prefix_list_ids",
            "self",
        )
        source_semantics_match = (
            body.get("type") == finding.rule.direction
            and attributes.get("type") == finding.rule.direction
            and _protocol_matches(body.get("protocol"), finding.rule.protocol)
            and _protocol_matches(attributes.get("protocol"), finding.rule.protocol)
        )
    else:
        source_attribute = "cidr_ipv6" if finding.rule.source == "::/0" else "cidr_ipv4"
        source_matches = (
            body.get(source_attribute) == finding.rule.source
            and attributes.get(source_attribute) == finding.rule.source
        )
        other_sources = (
            "cidr_ipv4" if source_attribute == "cidr_ipv6" else "cidr_ipv6",
            "referenced_security_group_id",
            "prefix_list_id",
        )
        source_semantics_match = (
            finding.rule.direction == "ingress"
            and _protocol_matches(body.get("ip_protocol"), finding.rule.protocol)
            and _protocol_matches(attributes.get("ip_protocol"), finding.rule.protocol)
        )
    return bool(
        source_matches
        and all(
            _empty_source(body.get(key)) and _empty_source(attributes.get(key))
            for key in other_sources
        )
        and source_semantics_match
        and _int_value(body.get("from_port")) == finding.rule.from_port
        and _int_value(attributes.get("from_port")) == finding.rule.from_port
        and _int_value(body.get("to_port")) == finding.rule.to_port
        and _int_value(attributes.get("to_port")) == finding.rule.to_port
        and attributes.get("security_group_id") == finding.resource_id
        and _state_rule_id_matches(
            attributes,
            resource_type,
            provenance.security_group_rule_id,
        )
    )


def _inline_rule_matches(body: dict[str, Any], finding: SecurityFinding) -> bool:
    if "count" in body or "for_each" in body:
        return False
    matches = 0
    for ingress in _list_value(body.get("ingress")):
        if not isinstance(ingress, dict):
            continue
        if (
            _int_value(ingress.get("from_port")) == finding.rule.from_port
            and _int_value(ingress.get("to_port")) == finding.rule.to_port
            and _protocol_matches(ingress.get("protocol"), finding.rule.protocol)
            and finding.rule.source in _list_value(ingress.get("cidr_blocks"))
        ):
            matches += 1
    return matches == 1


def _state_rule_id_matches(
    attributes: dict[str, Any],
    resource_type: str,
    expected_rule_id: str,
) -> bool:
    if resource_type == "aws_security_group_rule":
        return attributes.get("security_group_rule_id") == expected_rule_id
    rule_ids = [
        value
        for value in (
            attributes.get("security_group_rule_id"),
            attributes.get("id"),
        )
        if isinstance(value, str) and value
    ]
    return bool(rule_ids) and all(rule_id == expected_rule_id for rule_id in rule_ids)


def _state_has_attribute(
    state_attributes: dict[str, list[dict[str, Any]]],
    address: str,
    attribute: str,
    expected: str,
) -> bool:
    values = state_attributes.get(address, [])
    return len(values) == 1 and values[0].get(attribute) == expected


def _single_source_matches(value: Any, expected: str) -> bool:
    return isinstance(value, list) and value == [expected]


def _empty_source(value: Any) -> bool:
    return value is None or value is False or value == [] or value == ""


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
