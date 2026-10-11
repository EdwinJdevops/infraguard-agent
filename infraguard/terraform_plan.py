"""Conservative SSH plan policy. Passing this policy does not authorize publication."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from infraguard.json_evidence import EvidenceError, read_json_object
from infraguard.models import SecurityFinding, TerraformPatch

PLAN_POLICY_VERSION = "public-ssh-plan-v1"
TERRAFORM_VERSION = "1.9.8"
AWS_PROVIDER_VERSION = "6.10.0"
AWS_PROVIDER = "registry.terraform.io/hashicorp/aws"


class PlanDisposition(StrEnum):
    UPDATE_CANDIDATE = "update_candidate"
    REPLACEMENT_REVIEW = "replacement_review"
    REJECT = "reject"


@dataclass(frozen=True)
class PlanPolicyResult:
    disposition: PlanDisposition
    reason: str
    actions: tuple[str, ...] = ()


def evaluate_public_ssh_plan(
    payload: bytes,
    finding: SecurityFinding,
    patch: TerraformPatch,
    expected_attributes: dict[str, Any],
) -> PlanPolicyResult:
    try:
        plan = read_json_object(payload, max_bytes=32 * 1024 * 1024)
        return _evaluate(plan, finding, patch, expected_attributes)
    except EvidenceError as exc:
        return PlanPolicyResult(PlanDisposition.REJECT, str(exc))
    except (TypeError, ValueError, AttributeError, RecursionError, IndexError):
        return PlanPolicyResult(PlanDisposition.REJECT, "invalid_plan_structure")


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise EvidenceError(code)


def _object(value: Any) -> dict[str, Any]:
    _require(isinstance(value, dict), "invalid_plan_structure")
    return value


def _equal(left: Any, right: Any) -> bool:
    # Python treats True == 1: JSON evidence must preserve their different types.
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def _attributes(value: dict[str, Any], ignored: set[str] | None = None) -> dict[str, Any]:
    # Terraform may add absent optional schema attributes as null during state decoding.
    return {k: v for k, v in value.items() if v is not None and k not in (ignored or set())}


def _no_unknown(value: Any) -> bool:
    if isinstance(value, dict):
        return all(_no_unknown(v) for v in value.values())
    if isinstance(value, list):
        return all(_no_unknown(v) for v in value)
    return value is False


def _evaluate(
    plan: dict[str, Any],
    finding: SecurityFinding,
    patch: TerraformPatch,
    expected_attributes: dict[str, Any],
) -> PlanPolicyResult:
    _require(plan.get("format_version") == "1.2", "unsupported_plan_format")
    _require(plan.get("terraform_version") == TERRAFORM_VERSION, "terraform_version_mismatch")
    _require(
        plan.get("complete") is True and plan.get("errored") is False, "incomplete_or_errored_plan"
    )
    _require(plan.get("applyable") is True, "non_actionable_plan")
    _require(
        plan.get("resource_drift", []) == [] and plan.get("deferred_changes", []) == [],
        "drift_or_deferred_changes",
    )
    _require(finding.has_verified_provenance(), "unverified_finding")
    _require(patch.source_before == finding.rule.source, "patch_finding_mismatch")
    changes = plan.get("resource_changes")
    _require(isinstance(changes, list) and bool(changes), "missing_resource_changes")
    target = None
    addresses = set()
    for item in changes:
        entry = _object(item)
        address = entry.get("address")
        _require(
            isinstance(address, str) and address not in addresses,
            "duplicate_or_invalid_plan_address",
        )
        addresses.add(address)
        _require(
            not any(k in entry for k in ("previous_address", "deposed")), "move_or_deposed_resource"
        )
        change = _object(entry.get("change"))
        _require(
            "importing" not in change and "generated_config" not in entry,
            "import_or_generated_configuration",
        )
        if address == patch.resource_address:
            target = entry
        else:
            _require(change.get("actions") == ["no-op"], "unrelated_resource_change")
            _require(_equal(change.get("before"), change.get("after")), "inconsistent_noop")
            _require(_no_unknown(change.get("after_unknown", {})), "unknown_unrelated_value")

    _require(target is not None, "target_missing_from_plan")
    resource_type, resource_name = patch.resource_address.split(".", 1)
    legacy = resource_type == "aws_security_group_rule"
    _require(
        resource_type in {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"},
        "unsupported_resource_type",
    )
    _require(
        target.get("mode") == "managed"
        and target.get("type") == resource_type
        and target.get("name") == resource_name
        and target.get("provider_name") == AWS_PROVIDER,
        "target_identity_mismatch",
    )
    _require(
        not any(k in target for k in ("module_address", "index")), "unsupported_target_instance"
    )
    change = _object(target.get("change"))
    before, after = _object(change.get("before")), _object(change.get("after"))
    _require(_equal(_attributes(before), _attributes(expected_attributes)), "plan_state_mismatch")
    _require(before.get("security_group_id") == finding.resource_id, "plan_group_mismatch")
    _require(
        before.get("security_group_rule_id") == finding.provenance.security_group_rule_id,
        "plan_rule_id_mismatch",
    )
    _require(
        type(before.get("from_port")) is int
        and type(before.get("to_port")) is int
        and before["from_port"] == finding.rule.from_port
        and before["to_port"] == finding.rule.to_port,
        "plan_ports_mismatch",
    )
    protocol = "protocol" if legacy else "ip_protocol"
    _require(str(before.get(protocol)).lower() in {"tcp", "6"}, "plan_protocol_mismatch")
    _require(not legacy or before.get("type") == "ingress", "plan_direction_mismatch")
    source = (
        ("ipv6_cidr_blocks" if patch.source_before == "::/0" else "cidr_blocks")
        if legacy
        else ("cidr_ipv6" if patch.source_before == "::/0" else "cidr_ipv4")
    )
    old = [patch.source_before] if legacy else patch.source_before
    new = [patch.replacement_source] if legacy else patch.replacement_source
    _require(before.get(source) == old and after.get(source) == new, "plan_source_mismatch")
    unknown = _object(change.get("after_unknown"))
    if legacy:
        _require(change.get("actions") == ["delete", "create"], "unexpected_legacy_actions")
        _require(change.get("replace_paths") == [[source]], "unexpected_replacement_trigger")
        # Only the replacement's computed IDs may become unknown, never rule semantics.
        allowed_unknown = {"id", "security_group_rule_id"}
        _require(
            all(k in allowed_unknown and v is True or _no_unknown(v) for k, v in unknown.items()),
            "unknown_rule_semantics",
        )
        ignored = {k for k, v in unknown.items() if v is True and k in allowed_unknown}
        result = PlanDisposition.REPLACEMENT_REVIEW
        reason = "legacy_rule_replacement_requires_disruption_review"
    else:
        _require(change.get("actions") == ["update"], "unexpected_ingress_actions")
        _require(not change.get("replace_paths"), "unexpected_replacement_trigger")
        _require(_no_unknown(unknown), "unknown_rule_semantics")
        ignored = set()
        result, reason = PlanDisposition.UPDATE_CANDIDATE, "only_approved_rule_source_changes"
    _require(
        _equal(_attributes(before, ignored | {source}), _attributes(after, ignored | {source})),
        "unexpected_target_attribute_change",
    )
    _validate_values(plan, changes, patch.resource_address, ignored)
    configuration = _object(_object(plan.get("configuration")).get("root_module"))
    _require(not configuration.get("module_calls"), "unsupported_plan_module")
    configured = configuration.get("resources")
    _require(isinstance(configured, list), "invalid_plan_configuration")
    matches = [r for r in configured if _object(r).get("address") == patch.resource_address]
    _require(len(matches) == 1, "configured_target_missing_or_duplicate")
    configured_target = matches[0]
    _require(
        configured_target.get("provider_config_key") == "aws"
        and not any(k in configured_target for k in ("count_expression", "for_each_expression")),
        "unsupported_plan_configuration",
    )
    expressions = _object(configured_target.get("expressions"))
    _require(
        _object(expressions.get(source)).get("constant_value") == new
        and _object(expressions.get("security_group_id")).get("constant_value")
        == finding.resource_id,
        "plan_configuration_mismatch",
    )
    outputs = plan.get("output_changes", {})
    _require(isinstance(outputs, dict), "invalid_output_changes")
    for item in outputs.values():
        output = _object(item)
        _require(
            output.get("actions") == ["no-op"]
            and _equal(output.get("before"), output.get("after"))
            and _no_unknown(output.get("after_unknown", False)),
            "output_change",
        )
    checks = plan.get("checks", [])
    _require(
        isinstance(checks, list) and all(_object(c).get("status") == "pass" for c in checks),
        "failed_or_unknown_check",
    )
    return PlanPolicyResult(result, reason, tuple(change["actions"]))


def _validate_values(plan: dict, changes: list, target: str, ignored: set[str]) -> None:
    """Reject disagreement between the change summary and the values representations."""
    prior = _object(_object(plan.get("prior_state")).get("values"))
    planned = _object(plan.get("planned_values"))
    _require(_equal(prior.get("outputs", {}), planned.get("outputs", {})), "output_values_change")
    for section, key in (("prior_state", "before"), ("planned_values", "after")):
        values = _object(plan.get(section))
        if section == "prior_state":
            values = _object(values.get("values"))
        root = _object(values.get("root_module"))
        _require(not root.get("child_modules"), "unsupported_plan_module")
        resources = root.get("resources")
        _require(isinstance(resources, list), "missing_plan_values")
        by_address = {}
        for item in resources:
            resource = _object(item)
            address = resource.get("address")
            _require(
                isinstance(address, str) and address not in by_address,
                "duplicate_or_invalid_values_address",
            )
            by_address[address] = resource
        _require(set(by_address) == {r["address"] for r in changes}, "plan_values_scope_mismatch")
        for entry in changes:
            resource = by_address[entry["address"]]
            _require(
                all(
                    resource.get(k) == entry.get(k)
                    for k in ("mode", "type", "name", "provider_name")
                ),
                "plan_values_identity_mismatch",
            )
            skip = ignored if entry["address"] == target and key == "after" else set()
            _require(
                _equal(
                    _attributes(_object(resource.get("values")), skip),
                    _attributes(_object(entry["change"].get(key)), skip),
                ),
                "plan_values_mismatch",
            )
