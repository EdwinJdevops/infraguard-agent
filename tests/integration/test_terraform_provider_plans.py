"""Credential-free real-provider plans of generated patches; never apply or refresh.

Opt in with INFRAGUARD_TERRAFORM_INTEGRATION=1. CI runs this as a separate required-to-pass job.
These tests use synthetic state and do not establish live AWS behavior or state authenticity.
"""
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from infraguard.patches import write_patch
from infraguard.runbook import run_public_ssh_remediation
from tests.test_terraform_ownership import public_ssh_finding

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "terraform"
TERRAFORM_VERSION = "1.9.8"
PROVIDER_VERSION = "6.10.0"
pytestmark = pytest.mark.skipif(
    os.environ.get("INFRAGUARD_TERRAFORM_INTEGRATION") != "1",
    reason="real Terraform provider integration must be explicitly enabled",
)


def tf(binary: str, root: Path, env: dict[str, str], *args: str) -> str:
    result = subprocess.run(
        [binary, *args], cwd=root, env=env, text=True, capture_output=True, timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.fixture(scope="module")
def provider(tmp_path_factory):
    binary = shutil.which("terraform")
    assert binary is not None, "integration enabled but Terraform is not installed"
    root = tmp_path_factory.mktemp("offline-provider")
    shutil.copytree(FIXTURES / "offline_provider", root, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".terraform"))
    env = {
        "PATH": os.environ["PATH"], "HOME": str(root), "TF_IN_AUTOMATION": "1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_SHARED_CREDENTIALS_FILE": str(root / "no-credentials"),
        "AWS_CONFIG_FILE": str(root / "no-config"),
    }
    version = json.loads(tf(binary, root, env, "version", "-json"))
    assert version["terraform_version"] == TERRAFORM_VERSION
    tf(binary, root, env, "init", "-backend=false", "-input=false",
       "-lockfile=readonly", "-no-color")
    schema = json.loads(tf(binary, root, env, "providers", "schema", "-json"))
    return binary, root, env, schema["provider_schemas"]["registry.terraform.io/hashicorp/aws"]


@pytest.mark.parametrize("fixture,expected_actions", [
    ("standalone_public_ssh", ["delete", "create"]),
    ("vpc_ingress_public_ssh", ["update"]),
])
def test_generated_patch_has_expected_provider_plan(
    tmp_path: Path, provider, fixture: str, expected_actions: list[str]
) -> None:
    binary, installed, env, provider_schema = provider
    shutil.copytree(FIXTURES / fixture, tmp_path, dirs_exist_ok=True)
    shutil.copyfile(installed / "provider.tf", tmp_path / "provider.tf")
    shutil.copyfile(installed / ".terraform.lock.hcl", tmp_path / ".terraform.lock.hcl")
    # Reuse the verified installed binary without another download.
    (tmp_path / ".terraform").symlink_to(installed / ".terraform", target_is_directory=True)
    data = json.loads((tmp_path / "terraform-state.json").read_text())
    resource = data["resources"][0]
    schema = provider_schema["resource_schemas"][resource["type"]]
    instance = resource["instances"][0]
    instance["schema_version"] = schema["version"]
    # Encode every attribute against the actual provider schema, using only synthetic values.
    attrs = dict.fromkeys(schema["block"]["attributes"])
    attrs.update(instance["attributes"])
    if "region" in attrs:
        attrs["region"] = "us-east-1"
    if fixture == "standalone_public_ssh":
        attrs.update(self=False, ipv6_cidr_blocks=[], prefix_list_ids=[],
                     description="", source_security_group_id="")
    else:
        attrs.update(
            arn="arn:aws:ec2:us-east-1:123456789012:security-group-rule/sgr-1234567890abcdef0",
            tags=None, tags_all={},
        )
    instance["attributes"] = attrs
    state = tmp_path / "terraform.tfstate"
    state.write_text(json.dumps(data))
    tf(binary, tmp_path, env, "validate", "-no-color")

    def plan(name: str) -> tuple[dict, str]:
        path = tmp_path / name
        tf(binary, tmp_path, env, "plan", "-refresh=false", "-input=false", "-no-color",
           f"-out={path}")
        payload = tf(binary, tmp_path, env, "show", "-json", str(path))
        return json.loads(payload), hashlib.sha256(payload.encode()).hexdigest()

    before, _ = plan("before.plan")
    baseline_changes = before.get("resource_changes", [])
    diagnostics = [{
        "address": c["address"], "actions": c["change"]["actions"],
        "changed_attributes": [k for k, v in (c["change"].get("before") or {}).items()
                               if v != (c["change"].get("after") or {}).get(k)],
    } for c in baseline_changes]
    assert len(baseline_changes) == 1, diagnostics
    assert all(c["change"]["actions"] == ["no-op"] for c in baseline_changes), diagnostics
    run = run_public_ssh_remediation(
        public_ssh_finding(), tmp_path, "10.20.30.40/32", state, {"10.20.30.40/32"}
    )
    assert run.can_open_pr and run.patch is not None
    write_patch(run.patch)
    tf(binary, tmp_path, env, "validate", "-no-color")
    after, digest = plan("after.plan")
    changes = [c for c in after["resource_changes"] if c["change"]["actions"] != ["no-op"]]
    assert len(changes) == 1
    change = changes[0]
    assert change["address"] == run.patch.resource_address
    assert change["change"]["actions"] == expected_actions
    key = "cidr_blocks" if fixture == "standalone_public_ssh" else "cidr_ipv4"
    expected = ["10.20.30.40/32"] if key == "cidr_blocks" else "10.20.30.40/32"
    assert change["change"]["after"][key] == expected
    for key in ("security_group_id", "from_port", "to_port"):
        assert change["change"]["before"][key] == change["change"]["after"][key]
    print(json.dumps({
        "fixture": fixture, "terraform": TERRAFORM_VERSION, "aws_provider": PROVIDER_VERSION,
        "actions": expected_actions, "replacement_paths": change["change"].get("replace_paths", []),
        "plan_json_sha256": digest, "refresh": False, "apply": False, "synthetic_state": True,
    }, sort_keys=True))
