from __future__ import annotations

from io import StringIO

import hcl2

from infraguard.models import PatchValidation, TerraformPatch


def validate_public_ssh_patch(patch: TerraformPatch) -> PatchValidation:
    checks = {
        "before_target_contains_public_ssh": False,
        "after_parses_as_hcl": False,
        "after_removes_target_public_ssh": False,
        "after_contains_replacement_source": False,
        "target_rule_remains_ssh_ingress": False,
        "only_expected_source_changed": False,
        "diff_is_present": bool(patch.diff.strip()),
    }
    errors: list[str] = []

    try:
        before_parsed = hcl2.load(StringIO(patch.before))
        after_parsed = hcl2.load(StringIO(patch.after))
        checks["after_parses_as_hcl"] = isinstance(after_parsed, dict)
        before_rule = _resource_body(before_parsed, patch.resource_address)
        after_rule = _resource_body(after_parsed, patch.resource_address)
        before_sources = _rule_sources(before_rule, patch.resource_address)
        after_sources = _rule_sources(after_rule, patch.resource_address)
        checks["before_target_contains_public_ssh"] = patch.source_before in before_sources
        checks["after_removes_target_public_ssh"] = not ({"0.0.0.0/0", "::/0"} & set(after_sources))
        checks["after_contains_replacement_source"] = patch.replacement_source in after_sources
        checks["target_rule_remains_ssh_ingress"] = _is_ssh_ingress(
            after_rule,
            patch.resource_address,
        )
    except Exception as exc:
        errors.append(f"patched HCL does not parse: {exc}")

    checks["only_expected_source_changed"] = _only_expected_source_changed(patch)

    if not checks["diff_is_present"]:
        errors.append("patch diff is empty")

    return PatchValidation(
        passed=all(checks.values()) and not errors,
        checks=checks,
        errors=errors,
    )


def _resource_body(parsed: dict, resource_address: str) -> dict:
    resource_type, resource_name = resource_address.split(".", 1)
    for group in parsed.get("resource", []):
        body = group.get(resource_type, {}).get(resource_name)
        if isinstance(body, dict):
            return body
    raise ValueError(f"resource not found after parsing: {resource_address}")


def _rule_sources(body: dict, resource_address: str) -> list[str]:
    resource_type = resource_address.split(".", 1)[0]
    if resource_type == "aws_security_group_rule":
        values = [body.get("cidr_blocks", []), body.get("ipv6_cidr_blocks", [])]
        return [
            item
            for value in values
            if isinstance(value, list)
            for item in value
            if isinstance(item, str)
        ]
    if resource_type == "aws_vpc_security_group_ingress_rule":
        return [
            value
            for value in (body.get("cidr_ipv4"), body.get("cidr_ipv6"))
            if isinstance(value, str)
        ]
    return []


def _is_ssh_ingress(body: dict, resource_address: str) -> bool:
    resource_type = resource_address.split(".", 1)[0]
    if resource_type == "aws_security_group_rule":
        direction_ok = body.get("type") == "ingress"
        protocol = body.get("protocol")
    else:
        direction_ok = True
        protocol = body.get("ip_protocol")
    return (
        direction_ok
        and str(protocol).lower() == "tcp"
        and isinstance(body.get("from_port"), int)
        and isinstance(body.get("to_port"), int)
        and body["from_port"] <= 22 <= body["to_port"]
    )


def _only_expected_source_changed(patch: TerraformPatch) -> bool:
    removed = [
        line[1:]
        for line in patch.diff.splitlines()
        if line.startswith("-") and not line.startswith("---")
    ]
    added = [
        line[1:]
        for line in patch.diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    if len(removed) != 1 or len(added) != 1:
        return False
    return (
        patch.source_before in removed[0]
        and patch.replacement_source in added[0]
        and removed[0].replace(patch.source_before, patch.replacement_source) == added[0]
    )
