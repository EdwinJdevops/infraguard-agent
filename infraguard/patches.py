from __future__ import annotations

from pathlib import Path
import difflib

from infraguard.models import Decision, Ownership, RemediationDecision, TerraformPatch


class PatchError(ValueError):
    """Raised when a remediation decision cannot be converted into a safe patch."""


def generate_standalone_public_ssh_patch(decision: RemediationDecision) -> TerraformPatch:
    if decision.decision != Decision.AUTO_PR:
        raise PatchError(f"cannot generate patch for decision={decision.decision}")
    if decision.ownership != Ownership.TERRAFORM_STANDALONE_RULE:
        raise PatchError("only standalone Terraform rule patches are supported")
    if decision.terraform_resource is None or decision.terraform_resource.file_path is None:
        raise PatchError("terraform resource file path is required")
    if decision.replacement_source is None:
        raise PatchError("replacement source is required")

    file_path = Path(decision.terraform_resource.file_path)
    before = file_path.read_text(encoding="utf-8")
    after = _replace_public_source_in_resource(
        source=before,
        resource_address=decision.terraform_resource.address,
        old_source=decision.finding.rule.source,
        new_source=decision.replacement_source,
    )
    if before == after:
        raise PatchError("patch did not modify Terraform source")
    if _resource_contains_public_ssh_source(after, decision.terraform_resource.address, decision.finding.rule.source):
        raise PatchError("patch output still contains public SSH source in target resource")

    return TerraformPatch(
        file_path=str(file_path),
        before=before,
        after=after,
        resource_address=decision.terraform_resource.address,
        summary=(
            f"Replace public SSH source {decision.finding.rule.source} with "
            f"{decision.replacement_source} in {decision.terraform_resource.address}"
        ),
        diff=_unified_diff(str(file_path), before, after),
    )


def write_patch(patch: TerraformPatch) -> None:
    Path(patch.file_path).write_text(patch.after, encoding="utf-8")


def _replace_public_source_in_resource(
    source: str,
    resource_address: str,
    old_source: str,
    new_source: str,
) -> str:
    resource_type, resource_name = resource_address.split(".", 1)
    start = _find_resource_start(source, resource_type, resource_name)
    end = _find_block_end(source, start)
    block = source[start:end]

    if resource_type == "aws_security_group_rule":
        patched_block = block.replace(f'"{old_source}"', f'"{new_source}"', 1)
    elif resource_type == "aws_vpc_security_group_ingress_rule":
        patched_block = block.replace(f'cidr_ipv4         = "{old_source}"', f'cidr_ipv4         = "{new_source}"', 1)
        if patched_block == block:
            patched_block = block.replace(f'cidr_ipv4 = "{old_source}"', f'cidr_ipv4 = "{new_source}"', 1)
    else:
        raise PatchError(f"unsupported standalone resource type: {resource_type}")

    if patched_block == block:
        raise PatchError(f"could not find public source {old_source} in {resource_address}")

    return source[:start] + patched_block + source[end:]


def _resource_contains_public_ssh_source(source: str, resource_address: str, public_source: str) -> bool:
    resource_type, resource_name = resource_address.split(".", 1)
    start = _find_resource_start(source, resource_type, resource_name)
    end = _find_block_end(source, start)
    return f'"{public_source}"' in source[start:end]


def _unified_diff(file_path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
    )


def _find_resource_start(source: str, resource_type: str, resource_name: str) -> int:
    candidates = [
        f'resource "{resource_type}" "{resource_name}"',
        f"resource '{resource_type}' '{resource_name}'",
    ]
    for candidate in candidates:
        index = source.find(candidate)
        if index != -1:
            return index
    raise PatchError(f"resource block not found: {resource_type}.{resource_name}")


def _find_block_end(source: str, start: int) -> int:
    opening = source.find("{", start)
    if opening == -1:
        raise PatchError("resource block has no opening brace")

    depth = 0
    in_string = False
    escape = False
    for index in range(opening, len(source)):
        char = source[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    raise PatchError("resource block has no closing brace")
