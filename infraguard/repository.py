"""Read Terraform inputs from Git objects at an authorized SHA, never the working tree."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from infraguard.json_evidence import EvidenceError


@dataclass(frozen=True)
class SourceFile:
    path: str
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class RepositorySnapshot:
    repository: str
    commit_sha: str
    terraform_directory: str
    files: tuple[SourceFile, ...] = field(repr=False)

    def source_digest(self) -> str:
        validate_files(self.files)
        inventory = [
            {"path": f.path, "sha256": hashlib.sha256(f.content).hexdigest()}
            for f in sorted(self.files, key=lambda f: f.path)
        ]
        return hashlib.sha256(
            json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def validate_files(files: tuple[SourceFile, ...]) -> None:
    if not isinstance(files, tuple) or not 1 <= len(files) <= 64:
        raise EvidenceError("invalid_source_inventory")
    names = set()
    total = 0
    for file in files:
        if (
            not isinstance(file, SourceFile)
            or not isinstance(file.path, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", file.path)
            or file.path in {".", ".."}
            or file.path in names
            or not isinstance(file.content, bytes)
            or len(file.content) > 2 * 1024 * 1024
        ):
            raise EvidenceError("invalid_source_inventory")
        if not _terraform_input(file.path):
            raise EvidenceError("unsupported_source_file")
        names.add(file.path)
        total += len(file.content)
    if total > 8 * 1024 * 1024:
        raise EvidenceError("source_inventory_too_large")


def _terraform_input(name: str) -> bool:
    return name.endswith((".tf", ".tf.json", ".auto.tfvars", ".auto.tfvars.json")) or name in {
        ".terraform.lock.hcl",
        "terraform.tfvars",
        "terraform.tfvars.json",
    }


def capture_repository_snapshot(
    repository_path: Path,
    *,
    repository: str,
    commit_sha: str,
    terraform_directory: str = ".",
) -> RepositorySnapshot:
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise EvidenceError("invalid_commit_sha")
    root = PurePosixPath(terraform_directory)
    if (
        not terraform_directory
        or root.is_absolute()
        or ".." in root.parts
        or "\\" in terraform_directory
        or str(root) != terraform_directory
    ):
        raise EvidenceError("invalid_terraform_directory")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }

    def git(*args: str) -> bytes:
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=repository_path,
                env=env,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvidenceError("git_snapshot_unavailable") from exc
        if result.returncode:
            raise EvidenceError("git_snapshot_unavailable")
        return result.stdout

    resolved = git("rev-parse", "--verify", f"{commit_sha}^{{commit}}").strip().decode("ascii")
    if resolved != commit_sha:
        raise EvidenceError("commit_identity_mismatch")
    tree = commit_sha if root == PurePosixPath(".") else f"{commit_sha}:{root}"
    files = []
    for entry in git("ls-tree", "-z", tree).split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        try:
            path = name.decode("utf-8")
        except UnicodeError as exc:
            raise EvidenceError("invalid_source_filename") from exc
        if not _terraform_input(path):
            continue
        mode, kind, sha = metadata.decode("ascii").split(" ")
        if mode != "100644" or kind != "blob":
            raise EvidenceError("unsupported_git_source_mode")
        if int(git("cat-file", "-s", sha)) > 2 * 1024 * 1024 or len(files) >= 64:
            raise EvidenceError("source_inventory_too_large")
        files.append(SourceFile(path, git("cat-file", "blob", sha)))
    snapshot = RepositorySnapshot(repository, commit_sha, terraform_directory, tuple(files))
    validate_files(snapshot.files)
    return snapshot
