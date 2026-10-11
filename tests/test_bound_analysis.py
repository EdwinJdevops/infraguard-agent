"""Adversarial evidence tests. All source, state, identities, and plans are synthetic."""

import copy
import hashlib
import json
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from infraguard.analysis import (
    AnalysisExpectations,
    PlanArtifact,
    StateSnapshot,
    evaluate_bound_plan,
    prepare_public_ssh_analysis,
)
from infraguard.json_evidence import EvidenceError, read_json_object
from infraguard.repository import RepositorySnapshot, SourceFile, capture_repository_snapshot
from infraguard.terraform_plan import PlanDisposition, evaluate_public_ssh_plan
from tests.test_terraform_ownership import public_ssh_finding

FIXTURES = Path(__file__).parent / "fixtures" / "terraform"
NOW = datetime(2026, 10, 11, 12, tzinfo=UTC)
REPLACEMENT = "10.20.30.40/32"


def sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def inputs(fixture="vpc_ingress_public_ssh"):
    root = FIXTURES / fixture
    files = tuple(SourceFile(name, (root / name).read_bytes()) for name in ["security-groups.tf"])
    lock = SourceFile(
        ".terraform.lock.hcl", (FIXTURES / "offline_provider" / ".terraform.lock.hcl").read_bytes()
    )
    snapshot = RepositorySnapshot("example/infra", "a" * 40, ".", (*files, lock))
    state = StateSnapshot(
        "test-backend", "test-workspace", NOW, (root / "terraform-state.json").read_bytes()
    )
    decoded = json.loads(state.content)
    finding = public_ssh_finding()
    finding = replace(
        finding, provenance=replace(finding.provenance, observed_at=NOW, verified_at=NOW)
    )
    expectations = AnalysisExpectations(
        snapshot.repository,
        snapshot.commit_sha,
        ".",
        snapshot.source_digest(),
        sha(lock.content),
        state.backend_alias,
        state.workspace,
        sha(state.content),
        decoded["lineage"],
        decoded["serial"],
        (REPLACEMENT,),
        "test-policy-v1",
    )
    return dict(
        snapshot=snapshot,
        state=state,
        finding=finding,
        expectations=expectations,
        replacement_source=REPLACEMENT,
        now=NOW,
    )


def prepare(fixture="vpc_ingress_public_ssh"):
    return prepare_public_ssh_analysis(**inputs(fixture))


def plan_for(prepared):
    state = json.loads(prepared.state_content)
    resource = state["resources"][0]
    before = resource["instances"][0]["attributes"]
    after = copy.deepcopy(before)
    legacy = resource["type"] == "aws_security_group_rule"
    source = "cidr_blocks" if legacy else "cidr_ipv4"
    after[source] = [REPLACEMENT] if legacy else REPLACEMENT
    unknown = {}
    if legacy:
        for key in ["id", "security_group_rule_id"]:
            after[key] = None
            unknown[key] = True
    identity = dict(
        address=prepared.patch.resource_address,
        mode="managed",
        type=resource["type"],
        name=resource["name"],
        provider_name="registry.terraform.io/hashicorp/aws",
    )
    entry = dict(
        **identity,
        change=dict(
            actions=["delete", "create"] if legacy else ["update"],
            before=before,
            after=after,
            after_unknown=unknown,
        ),
    )
    if legacy:
        entry["change"]["replace_paths"] = [[source]]
    return dict(
        format_version="1.2",
        terraform_version="1.9.8",
        complete=True,
        errored=False,
        applyable=True,
        timestamp=NOW.isoformat(),
        resource_changes=[entry],
        prior_state=dict(
            values=dict(root_module=dict(resources=[dict(**identity, values=before)]))
        ),
        planned_values=dict(root_module=dict(resources=[dict(**identity, values=after)])),
        configuration=dict(
            root_module=dict(
                resources=[
                    dict(
                        address=identity["address"],
                        provider_config_key="aws",
                        expressions={
                            source: {"constant_value": after[source]},
                            "security_group_id": {"constant_value": before["security_group_id"]},
                        },
                    )
                ]
            )
        ),
    )


def artifact(prepared, plan):
    return PlanArtifact(prepared.manifest_sha256, NOW, "1.9.8", "6.10.0", json.dumps(plan).encode())


def disposition(prepared, plan):
    return evaluate_bound_plan(prepared, artifact(prepared, plan), now=NOW).policy.disposition


@pytest.mark.parametrize(
    "fixture,expected",
    [
        ("vpc_ingress_public_ssh", PlanDisposition.UPDATE_CANDIDATE),
        ("standalone_public_ssh", PlanDisposition.REPLACEMENT_REVIEW),
    ],
)
def test_only_narrow_rule_changes_are_review_candidates(fixture, expected):
    prepared = prepare(fixture)
    assert disposition(prepared, plan_for(prepared)) == expected
    evidence = evaluate_bound_plan(prepared, artifact(prepared, plan_for(prepared)), now=NOW)
    public = json.dumps(evidence.to_evidence())
    assert evidence.to_evidence()["publication"] == "not_attempted"
    assert evidence.to_evidence()["state_origin_attested"] is False
    for confidential in [
        "test-backend",
        "test-workspace",
        "security-groups.tf",
        REPLACEMENT,
        "sg-1234567890abcdef0",
        "sgr-1234567890abcdef0",
    ]:
        assert confidential not in public
    assert confidential not in repr(prepared)
    assert "/tmp/" not in prepared.patch.diff


@pytest.mark.parametrize(
    "key,value",
    [
        ("repository", "other/infra"),
        ("commit_sha", "b" * 40),
        ("terraform_directory", "other"),
        ("source_sha256", "b" * 64),
        ("lock_sha256", "b" * 64),
        ("backend_alias", "wrong"),
        ("workspace", "wrong"),
        ("state_sha256", "b" * 64),
        ("state_lineage", "wrong"),
        ("state_serial", 2),
        ("state_serial", True),
        ("max_input_age_seconds", 0),
        ("max_input_age_seconds", 901),
        ("max_input_age_seconds", True),
        ("policy_revision", ""),
        ("allowed_replacement_sources", ()),
        ("allowed_replacement_sources", ("10.0.0.0/8",)),
    ],
)
def test_coordinator_mismatches_reject_preparation(key, value):
    args = inputs()
    args["expectations"] = replace(args["expectations"], **{key: value})
    with pytest.raises(EvidenceError):
        prepare_public_ssh_analysis(**args)


@pytest.mark.parametrize(
    "component,offset",
    [
        ("state", -301),
        ("state", 1),
        ("finding", -301),
        ("finding", 1),
    ],
)
def test_old_or_future_inputs_reject(component, offset):
    args = inputs()
    time = NOW + timedelta(seconds=offset)
    if component == "state":
        args["state"] = replace(args["state"], collected_at=time)
    else:
        args["finding"] = replace(
            args["finding"],
            provenance=replace(args["finding"].provenance, observed_at=time, verified_at=time),
        )
    with pytest.raises(EvidenceError):
        prepare_public_ssh_analysis(**args)


@pytest.mark.parametrize(
    "mutation", ["state", "source", "patch", "before", "finding", "deadline", "manifest"]
)
def test_prepared_artifact_tampering_rejects(mutation):
    prepared = prepare()
    original_plan = artifact(prepared, plan_for(prepared))
    if mutation == "state":
        prepared = replace(prepared, state_content=prepared.state_content + b" ")
    elif mutation == "source":
        prepared = replace(
            prepared,
            source_files_after=(
                *prepared.source_files_after[:-1],
                replace(prepared.source_files_after[-1], content=b"changed"),
            ),
        )
    elif mutation == "patch":
        prepared = replace(
            prepared, patch=replace(prepared.patch, replacement_source="10.0.0.1/32")
        )
    elif mutation == "before":
        prepared = replace(prepared, patch=replace(prepared.patch, before="changed"))
    elif mutation == "finding":
        prepared = replace(prepared, finding=replace(prepared.finding, alert_id="another"))
    elif mutation == "deadline":
        prepared = replace(prepared, expires_at=NOW + timedelta(days=1))
    else:
        prepared = replace(prepared, manifest_json=prepared.manifest_json + b" ")
    assert (
        evaluate_bound_plan(prepared, original_plan, now=NOW).policy.disposition
        == PlanDisposition.REJECT
    )


@pytest.mark.parametrize(
    "mutation", ["manifest", "terraform", "provider", "created_before", "created_future", "expired"]
)
def test_plan_envelope_and_completion_deadline_reject(mutation):
    prepared = prepare()
    value = artifact(prepared, plan_for(prepared))
    now = NOW
    if mutation == "manifest":
        value = replace(value, input_manifest_sha256="b" * 64)
    elif mutation == "terraform":
        value = replace(value, terraform_version="1.10.0")
    elif mutation == "provider":
        value = replace(value, aws_provider_version="6.11.0")
    elif mutation == "created_before":
        value = replace(value, created_at=NOW - timedelta(seconds=1))
    elif mutation == "created_future":
        value = replace(value, created_at=NOW + timedelta(seconds=1))
    else:
        now += timedelta(seconds=301)
    assert (
        evaluate_bound_plan(prepared, value, now=now).policy.disposition == PlanDisposition.REJECT
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "incomplete",
        "errored",
        "format",
        "version",
        "no_action",
        "drift",
        "deferred",
        "missing_target",
        "duplicate",
        "other_change",
        "move",
        "deposed",
        "import",
        "module",
        "index",
        "wrong_group",
        "wrong_rule_id",
        "wrong_port",
        "port_bool",
        "wrong_protocol",
        "wrong_source",
        "wrong_actions",
        "unknown_port",
        "tags",
        "replacement",
        "output",
        "check",
        "missing_before",
        "wrong_values",
        "hidden_values",
        "child_module",
        "alias",
        "configured_source",
        "configured_group",
        "configured_count",
        "timestamp_missing",
        "timestamp_old",
        "timestamp_future",
        "timestamp_naive",
    ],
)
def test_unsafe_or_inconsistent_plans_reject(mutation):
    prepared = prepare()
    plan = plan_for(prepared)
    entry = plan["resource_changes"][0]
    change = entry["change"]
    config = plan["configuration"]["root_module"]["resources"][0]
    if mutation in {"incomplete", "errored", "format", "version", "no_action", "drift", "deferred"}:
        key, value = {
            "incomplete": ("complete", False),
            "errored": ("errored", True),
            "format": ("format_version", "1.3"),
            "version": ("terraform_version", "1.10.0"),
            "no_action": ("applyable", False),
            "drift": ("resource_drift", [{}]),
            "deferred": ("deferred_changes", [{}]),
        }[mutation]
        plan[key] = value
    elif mutation == "missing_target":
        plan["resource_changes"] = []
    elif mutation in {"duplicate", "other_change"}:
        other = copy.deepcopy(entry)
        if mutation == "other_change":
            other["address"] = "aws_instance.unrelated"
        plan["resource_changes"].append(other)
    elif mutation in {"move", "deposed", "import", "module", "index"}:
        key = {
            "move": "previous_address",
            "deposed": "deposed",
            "module": "module_address",
            "index": "index",
            "import": "importing",
        }[mutation]
        (change if mutation == "import" else entry)[key] = "unsupported"
    elif mutation in {"wrong_group", "wrong_rule_id", "wrong_port", "port_bool", "wrong_protocol"}:
        key, value = {
            "wrong_group": ("security_group_id", "sg-other"),
            "wrong_rule_id": ("security_group_rule_id", "sgr-other"),
            "wrong_port": ("from_port", 23),
            "port_bool": ("from_port", True),
            "wrong_protocol": ("ip_protocol", "udp"),
        }[mutation]
        change["before"][key] = value
    elif mutation == "wrong_source":
        change["after"]["cidr_ipv4"] = "0.0.0.0/0"
    elif mutation == "wrong_actions":
        change["actions"] = ["delete", "create"]
    elif mutation == "unknown_port":
        change["after_unknown"]["from_port"] = True
    elif mutation == "tags":
        change["after"]["tags"] = {"other": "change"}
    elif mutation == "replacement":
        change["replace_paths"] = [["cidr_ipv4"]]
    elif mutation == "output":
        plan["output_changes"] = {"test": {"actions": ["create"]}}
    elif mutation == "check":
        plan["checks"] = [{"status": "unknown"}]
    elif mutation == "missing_before":
        change["before"] = None
    elif mutation == "wrong_values":
        plan["planned_values"]["root_module"]["resources"][0]["values"] = {"different": "values"}
    elif mutation == "hidden_values":
        plan["planned_values"]["root_module"]["resources"].append(
            {"address": "aws_instance.hidden"}
        )
    elif mutation == "child_module":
        plan["planned_values"]["root_module"]["child_modules"] = [{}]
    elif mutation == "alias":
        config["provider_config_key"] = "aws.other"
    elif mutation in {"configured_source", "configured_group"}:
        config["expressions"] = copy.deepcopy(config["expressions"])
        key = "cidr_ipv4" if mutation == "configured_source" else "security_group_id"
        config["expressions"][key]["constant_value"] = "wrong"
    elif mutation == "configured_count":
        config["count_expression"] = {"constant_value": 1}
    elif mutation == "timestamp_missing":
        del plan["timestamp"]
    else:
        plan["timestamp"] = {
            "timestamp_old": (NOW - timedelta(seconds=1)).isoformat(),
            "timestamp_future": (NOW + timedelta(seconds=1)).isoformat(),
            "timestamp_naive": NOW.replace(tzinfo=None).isoformat(),
        }[mutation]
    assert disposition(prepared, plan) == PlanDisposition.REJECT, mutation


@pytest.mark.parametrize("key", ["security_group_id", "from_port", "source_security_group_id"])
def test_legacy_unknown_semantics_and_reverse_replacement_reject(key):
    prepared = prepare("standalone_public_ssh")
    plan = plan_for(prepared)
    plan["resource_changes"][0]["change"]["after_unknown"][key] = True
    assert disposition(prepared, plan) == PlanDisposition.REJECT
    plan = plan_for(prepared)
    plan["resource_changes"][0]["change"]["actions"] = ["create", "delete"]
    assert disposition(prepared, plan) == PlanDisposition.REJECT


@pytest.mark.parametrize(
    "payload",
    [
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":1e999}',
        b"[]",
        b"null",
        b"not json",
        b"\xff",
        b'{"x":' + b"[" * 1500 + b"]" * 1500 + b"}",
    ],
)
def test_strict_json_and_confidential_error_codes(payload):
    with pytest.raises(EvidenceError):
        read_json_object(payload, max_bytes=4096)
    prepared = prepare()
    result = evaluate_public_ssh_plan(payload, prepared.finding, prepared.patch, {})
    assert result.disposition == PlanDisposition.REJECT
    assert "NaN" not in result.reason


def test_size_limits_are_enforced_before_decoding():
    with pytest.raises(EvidenceError, match="artifact_size_or_type_invalid"):
        read_json_object(b'{"x":1}', max_bytes=2)


def git(root, *args):
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, check=True)
    return result.stdout.decode().strip()


def test_git_capture_uses_committed_objects_and_ignores_worktree_changes(tmp_path):
    git(tmp_path, "init")
    source = tmp_path / "main.tf"
    source.write_text("# committed\n")
    git(tmp_path, "add", "main.tf")
    git(
        tmp_path,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "synthetic source",
    )
    commit = git(tmp_path, "rev-parse", "HEAD")
    source.write_text("# changed\n")
    (tmp_path / "untracked.tf").write_text("# untracked\n")
    snapshot = capture_repository_snapshot(tmp_path, repository="example/infra", commit_sha=commit)
    assert snapshot.files == (SourceFile("main.tf", b"# committed\n"),)


@pytest.mark.parametrize("directory", ["../x", "/x", "x/../y", "x//y", "x\\y"])
def test_git_capture_rejects_noncanonical_roots(tmp_path, directory):
    with pytest.raises(EvidenceError, match="invalid_terraform_directory"):
        capture_repository_snapshot(
            tmp_path, repository="example/infra", commit_sha="a" * 40, terraform_directory=directory
        )


def test_git_capture_rejects_symlinked_source(tmp_path):
    git(tmp_path, "init")
    (tmp_path / "main.tf").symlink_to("/outside.tf")
    git(tmp_path, "add", "main.tf")
    git(
        tmp_path,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "synthetic symlink",
    )
    with pytest.raises(EvidenceError, match="unsupported_git_source_mode"):
        capture_repository_snapshot(
            tmp_path, repository="example/infra", commit_sha=git(tmp_path, "rev-parse", "HEAD")
        )
