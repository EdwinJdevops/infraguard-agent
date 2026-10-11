"""Bind an internal remediation candidate to exact source/state/lock/finding inputs.

The coordinator supplies expectations over a trusted internal boundary. This module cannot
authenticate a state backend or a GitHub repository. No HTTP request may provide expectations.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

import hcl2

from infraguard.json_evidence import EvidenceError, read_json_object
from infraguard.models import SecurityFinding, TerraformPatch
from infraguard.repository import RepositorySnapshot, SourceFile, validate_terraform_directory
from infraguard.runbook import run_public_ssh_remediation
from infraguard.terraform_plan import (
    AWS_PROVIDER,
    AWS_PROVIDER_VERSION,
    PLAN_POLICY_VERSION,
    TERRAFORM_VERSION,
    PlanDisposition,
    PlanPolicyResult,
    evaluate_public_ssh_plan,
)


@dataclass(frozen=True)
class StateSnapshot:
    backend_alias: str
    workspace: str
    collected_at: datetime
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class AnalysisExpectations:
    repository: str
    commit_sha: str
    terraform_directory: str
    source_sha256: str
    lock_sha256: str
    backend_alias: str
    workspace: str
    state_sha256: str
    state_lineage: str
    state_serial: int
    allowed_replacement_sources: tuple[str, ...]
    policy_revision: str
    max_input_age_seconds: int = 300


@dataclass(frozen=True)
class PreparedAnalysis:
    manifest_json: bytes = field(repr=False)
    manifest_sha256: str
    prepared_at: datetime
    expires_at: datetime
    finding: SecurityFinding = field(repr=False)
    patch: TerraformPatch = field(repr=False)
    source_files_after: tuple[SourceFile, ...] = field(repr=False)
    state_content: bytes = field(repr=False)


@dataclass(frozen=True)
class PlanArtifact:
    input_manifest_sha256: str
    created_at: datetime
    terraform_version: str
    aws_provider_version: str
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class AnalysisResult:
    input_manifest_sha256: str
    plan_sha256: str
    policy: PlanPolicyResult

    def to_evidence(self) -> dict[str, object]:
        # Deliberately never include state/plan values, provider configuration, or paths.
        return {
            "schema_version": "analysis-result-v1",
            "policy_version": PLAN_POLICY_VERSION,
            "input_manifest_sha256": self.input_manifest_sha256,
            "plan_sha256": self.plan_sha256,
            "disposition": self.policy.disposition.value,
            "reason": self.policy.reason,
            "actions": list(self.policy.actions),
            "publication": "not_attempted",
            "state_origin_attested": False,
        }


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _finding_digest(finding: SecurityFinding) -> str:
    return _sha(json.dumps(asdict(finding), sort_keys=True, default=str).encode())


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise EvidenceError(code)


def _aware(value: datetime) -> bool:
    return (
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None
    )


def prepare_public_ssh_analysis(
    *,
    snapshot: RepositorySnapshot,
    state: StateSnapshot,
    finding: SecurityFinding,
    expectations: AnalysisExpectations,
    replacement_source: str,
    now: datetime,
) -> PreparedAnalysis:
    _require(_aware(now) and _aware(state.collected_at), "timezone_required")
    validate_terraform_directory(expectations.terraform_directory)
    _require(
        all(
            isinstance(value, str) and 0 < len(value) <= 128
            for value in (
                expectations.repository,
                expectations.commit_sha,
                expectations.backend_alias,
                expectations.workspace,
                expectations.state_lineage,
                expectations.policy_revision,
                expectations.source_sha256,
                expectations.lock_sha256,
                expectations.state_sha256,
            )
        ),
        "invalid_coordinator_expectations",
    )
    _require(
        isinstance(state.content, bytes) and len(state.content) <= 16 * 1024 * 1024,
        "artifact_size_or_type_invalid",
    )
    _require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", expectations.repository) is not None
        and re.fullmatch(r"[0-9a-f]{40}", expectations.commit_sha) is not None,
        "invalid_repository_expectations",
    )
    _require(
        type(expectations.max_input_age_seconds) is int
        and 0 < expectations.max_input_age_seconds <= 900,
        "invalid_freshness_policy",
    )
    _require(
        type(expectations.state_serial) is int
        and expectations.state_serial >= 0
        and bool(expectations.state_lineage),
        "invalid_state_expectations",
    )
    _require(
        isinstance(expectations.allowed_replacement_sources, tuple)
        and bool(expectations.allowed_replacement_sources)
        and all(isinstance(source, str) for source in expectations.allowed_replacement_sources),
        "missing_operator_policy",
    )
    _require(
        all(
            re.fullmatch(r"[0-9a-f]{64}", digest) is not None
            for digest in (
                expectations.source_sha256,
                expectations.lock_sha256,
                expectations.state_sha256,
            )
        ),
        "invalid_expected_digest",
    )
    _require(
        (snapshot.repository, snapshot.commit_sha, snapshot.terraform_directory)
        == (
            expectations.repository,
            expectations.commit_sha,
            expectations.terraform_directory,
        ),
        "repository_binding_mismatch",
    )
    _require(snapshot.source_digest() == expectations.source_sha256, "source_digest_mismatch")
    _require(
        (state.backend_alias, state.workspace)
        == (
            expectations.backend_alias,
            expectations.workspace,
        ),
        "state_location_mismatch",
    )
    _require(_sha(state.content) == expectations.state_sha256, "state_digest_mismatch")
    decoded = read_json_object(state.content, max_bytes=16 * 1024 * 1024)
    _require(
        decoded.get("lineage") == expectations.state_lineage
        and type(decoded.get("serial")) is int
        and decoded["serial"] == expectations.state_serial,
        "state_generation_mismatch",
    )
    _require(finding.has_verified_provenance(), "unverified_finding")
    provenance = finding.provenance
    age = timedelta(seconds=expectations.max_input_age_seconds)
    _require(now - age <= state.collected_at <= now, "state_snapshot_stale_or_future")
    _require(now - age <= provenance.verified_at <= now, "finding_stale_or_future")
    lock = next((f.content for f in snapshot.files if f.path == ".terraform.lock.hcl"), None)
    _require(lock is not None and _sha(lock) == expectations.lock_sha256, "lock_digest_mismatch")
    try:
        providers = hcl2.load(StringIO(lock.decode("utf-8"))).get("provider", [])
    except Exception as exc:
        raise EvidenceError("invalid_provider_lock") from exc
    _require(
        isinstance(providers, list)
        and len(providers) == 1
        and isinstance(providers[0], dict)
        and set(providers[0]) == {AWS_PROVIDER},
        "unsupported_provider_lock",
    )
    provider = providers[0][AWS_PROVIDER]
    _require(isinstance(provider, dict), "invalid_provider_lock")
    _require(provider.get("version") == AWS_PROVIDER_VERSION, "aws_provider_version_mismatch")
    _require(
        isinstance(provider.get("hashes"), list)
        and bool(provider["hashes"])
        and all(
            isinstance(h, str) and re.fullmatch(r"(?:h1:[A-Za-z0-9+/=]+|zh:[0-9a-f]{64})", h)
            for h in provider["hashes"]
        ),
        "missing_or_invalid_provider_checksums",
    )
    with TemporaryDirectory(prefix="infraguard-analysis-") as directory:
        root = Path(directory) / "source"
        root.mkdir()
        for file in snapshot.files:
            (root / file.path).write_bytes(file.content)
        state_path = Path(directory) / "state.json"
        state_path.write_bytes(state.content)
        state_path.chmod(0o600)
        try:
            run = run_public_ssh_remediation(
                finding,
                root,
                replacement_source,
                state_path,
                expectations.allowed_replacement_sources,
            )
        except (ValueError, OSError) as exc:
            raise EvidenceError("local_remediation_gate_failed") from exc
        _require(run.can_open_pr and run.patch is not None, "local_remediation_gate_failed")
        relative_path = Path(run.patch.file_path).relative_to(root).as_posix()
        diff = "".join(
            difflib.unified_diff(
                run.patch.before.splitlines(keepends=True),
                run.patch.after.splitlines(keepends=True),
                fromfile=f"a/{relative_path}",
                tofile=f"b/{relative_path}",
            )
        )
        patch = replace(run.patch, file_path=relative_path, diff=diff)
    resource_type, resource_name = patch.resource_address.split(".", 1)
    owners = [
        r
        for r in decoded.get("resources", [])
        if r.get("mode") == "managed"
        and not r.get("module")
        and r.get("type") == resource_type
        and r.get("name") == resource_name
    ]
    _require(len(owners) == 1 and len(owners[0]["instances"]) == 1, "state_owner_mismatch")
    after = tuple(
        SourceFile(f.path, patch.after.encode() if f.path == relative_path else f.content)
        for f in snapshot.files
    )
    manifest = {
        "schema_version": "analysis-input-v1",
        "policy_version": PLAN_POLICY_VERSION,
        "repository": snapshot.repository,
        "commit_sha": snapshot.commit_sha,
        "terraform_directory": snapshot.terraform_directory,
        "source_sha256": expectations.source_sha256,
        "patched_source_sha256": replace(snapshot, files=after).source_digest(),
        "lock_sha256": expectations.lock_sha256,
        "state_sha256": expectations.state_sha256,
        "state_lineage": expectations.state_lineage,
        "state_serial": expectations.state_serial,
        "state_location_sha256": _sha(json.dumps([state.backend_alias, state.workspace]).encode()),
        "state_collected_at": state.collected_at.isoformat(),
        "finding_fingerprint": provenance.rule_fingerprint,
        "finding_sha256": _finding_digest(finding),
        "finding_verified_at": provenance.verified_at.isoformat(),
        "resource_address": patch.resource_address,
        "patch_sha256": _sha(json.dumps(asdict(patch), sort_keys=True).encode()),
        "patch_file": relative_path,
        "replacement_source": run.decision.replacement_source,
        "operator_policy_revision": expectations.policy_revision,
        "operator_policy_sha256": _sha(
            json.dumps(sorted(expectations.allowed_replacement_sources)).encode()
        ),
        "terraform_version": TERRAFORM_VERSION,
        "aws_provider_version": AWS_PROVIDER_VERSION,
        "prepared_at": now.isoformat(),
        "refresh": False,
        "expires_at": (min(state.collected_at, provenance.verified_at) + age).isoformat(),
    }
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return PreparedAnalysis(
        encoded,
        _sha(encoded),
        now,
        min(state.collected_at, provenance.verified_at) + age,
        finding,
        patch,
        after,
        state.content,
    )


def evaluate_bound_plan(
    prepared: PreparedAnalysis,
    artifact: PlanArtifact,
    *,
    now: datetime,
) -> AnalysisResult:
    try:
        _require(_aware(now) and _aware(artifact.created_at), "timezone_required")
        _require(
            _sha(prepared.manifest_json) == prepared.manifest_sha256, "input_manifest_tampered"
        )
        manifest = read_json_object(prepared.manifest_json, max_bytes=16 * 1024)
        _require(
            manifest.get("state_sha256") == _sha(prepared.state_content), "prepared_state_tampered"
        )
        source = RepositorySnapshot(
            manifest["repository"],
            manifest["commit_sha"],
            manifest["terraform_directory"],
            prepared.source_files_after,
        )
        _require(
            source.source_digest() == manifest.get("patched_source_sha256"),
            "prepared_source_tampered",
        )
        original = replace(
            source,
            files=tuple(
                SourceFile(f.path, prepared.patch.before.encode())
                if f.path == prepared.patch.file_path
                else f
                for f in source.files
            ),
        )
        _require(
            original.source_digest() == manifest.get("source_sha256"),
            "prepared_original_source_tampered",
        )
        patch_file = next((f for f in source.files if f.path == prepared.patch.file_path), None)
        _require(
            patch_file is not None
            and _sha(json.dumps(asdict(prepared.patch), sort_keys=True).encode())
            == manifest.get("patch_sha256")
            and patch_file.content == prepared.patch.after.encode()
            and prepared.patch.file_path == manifest.get("patch_file")
            and prepared.patch.resource_address == manifest.get("resource_address")
            and prepared.patch.source_before == prepared.finding.rule.source
            and prepared.patch.replacement_source == manifest.get("replacement_source"),
            "prepared_patch_tampered",
        )
        _require(
            prepared.finding.has_verified_provenance()
            and _finding_digest(prepared.finding) == manifest.get("finding_sha256")
            and prepared.finding.provenance.rule_fingerprint == manifest.get("finding_fingerprint")
            and prepared.finding.provenance.verified_at.isoformat()
            == manifest.get("finding_verified_at"),
            "prepared_finding_tampered",
        )
        _require(
            prepared.prepared_at.isoformat() == manifest.get("prepared_at")
            and prepared.expires_at.isoformat() == manifest.get("expires_at"),
            "prepared_deadline_tampered",
        )
        _require(artifact.input_manifest_sha256 == prepared.manifest_sha256, "plan_input_mismatch")
        _require(
            prepared.prepared_at <= artifact.created_at <= now <= prepared.expires_at,
            "analysis_expired_or_plan_timestamp_invalid",
        )
        _require(
            artifact.terraform_version == TERRAFORM_VERSION
            and artifact.aws_provider_version == AWS_PROVIDER_VERSION,
            "toolchain_mismatch",
        )
        plan = read_json_object(artifact.content, max_bytes=32 * 1024 * 1024)
        try:
            timestamp = datetime.fromisoformat(plan["timestamp"].replace("Z", "+00:00"))
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise EvidenceError("invalid_plan_timestamp") from exc
        _require(
            _aware(timestamp)
            and prepared.prepared_at.replace(microsecond=0) <= timestamp <= artifact.created_at,
            "plan_timestamp_outside_analysis",
        )
        state = read_json_object(prepared.state_content, max_bytes=16 * 1024 * 1024)
        resource_type, resource_name = prepared.patch.resource_address.split(".", 1)
        owners = [
            r
            for r in state["resources"]
            if r.get("mode") == "managed"
            and not r.get("module")
            and r.get("type") == resource_type
            and r.get("name") == resource_name
        ]
        _require(len(owners) == 1, "state_owner_mismatch")
        policy = evaluate_public_ssh_plan(
            artifact.content,
            prepared.finding,
            prepared.patch,
            owners[0]["instances"][0]["attributes"],
        )
    except EvidenceError as exc:
        policy = PlanPolicyResult(PlanDisposition.REJECT, str(exc))
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError, IndexError):
        policy = PlanPolicyResult(PlanDisposition.REJECT, "invalid_analysis_structure")
    return AnalysisResult(prepared.manifest_sha256, _sha(artifact.content), policy)
