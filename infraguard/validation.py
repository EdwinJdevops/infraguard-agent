from __future__ import annotations

from io import StringIO

import hcl2

from infraguard.models import PatchValidation, TerraformPatch


def validate_public_ssh_patch(patch: TerraformPatch) -> PatchValidation:
    checks = {
        "before_contains_public_ssh": False,
        "after_parses_as_hcl": False,
        "after_removes_target_public_ssh": False,
        "after_contains_replacement_source": False,
        "diff_is_present": bool(patch.diff.strip()),
    }
    errors: list[str] = []

    if '"0.0.0.0/0"' in patch.before or '"::/0"' in patch.before:
        checks["before_contains_public_ssh"] = True
    else:
        errors.append("before content did not contain a public SSH source")

    try:
        parsed = hcl2.load(StringIO(patch.after))
        checks["after_parses_as_hcl"] = isinstance(parsed, dict)
    except Exception as exc:
        errors.append(f"patched HCL does not parse: {exc}")

    if '"0.0.0.0/0"' not in patch.after and '"::/0"' not in patch.after:
        checks["after_removes_target_public_ssh"] = True
    else:
        errors.append("patched content still contains a public SSH source")

    if _replacement_sources_from_diff(patch):
        checks["after_contains_replacement_source"] = True
    else:
        errors.append("patched content does not include the replacement source from the diff")

    if not checks["diff_is_present"]:
        errors.append("patch diff is empty")

    return PatchValidation(
        passed=all(checks.values()) and not errors,
        checks=checks,
        errors=errors,
    )


def _replacement_sources_from_diff(patch: TerraformPatch) -> list[str]:
    added_lines = [line for line in patch.diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
    replacement_sources: list[str] = []
    for line in added_lines:
        if '"' not in line:
            continue
        parts = line.split('"')
        for index, part in enumerate(parts):
            if index % 2 == 1 and "/" in part and part not in {"0.0.0.0/0", "::/0"}:
                replacement_sources.append(part)
    return replacement_sources
