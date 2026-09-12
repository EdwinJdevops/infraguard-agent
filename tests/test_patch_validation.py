from pathlib import Path

from infraguard.models import SecurityFinding, SecurityGroupRule
from infraguard.patches import generate_standalone_public_ssh_patch
from infraguard.pipeline import plan_from_terraform
from infraguard.validation import validate_public_ssh_patch


FIXTURES = Path(__file__).parent / "fixtures" / "terraform"


def public_ssh_finding() -> SecurityFinding:
    return SecurityFinding(
        alert_id="alert-001",
        provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_security_group",
        resource_id="sg-1234567890abcdef0",
        rule=SecurityGroupRule(
            direction="ingress",
            protocol="tcp",
            from_port=22,
            to_port=22,
            source="0.0.0.0/0",
        ),
    )


def test_validates_standalone_patch_evidence(tmp_path: Path) -> None:
    source = FIXTURES / "standalone_public_ssh" / "security-groups.tf"
    target_dir = tmp_path / "terraform"
    target_dir.mkdir()
    target_file = target_dir / "security-groups.tf"
    target_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=target_dir,
        replacement_source="203.0.113.10/32",
    )
    patch = generate_standalone_public_ssh_patch(decision)
    validation = validate_public_ssh_patch(patch)

    assert validation.passed is True
    assert validation.errors == []
    assert validation.checks == {
        "before_contains_public_ssh": True,
        "after_parses_as_hcl": True,
        "after_removes_target_public_ssh": True,
        "after_contains_replacement_source": True,
        "diff_is_present": True,
    }


def test_validation_fails_when_after_still_contains_public_source(tmp_path: Path) -> None:
    source = FIXTURES / "standalone_public_ssh" / "security-groups.tf"
    target_dir = tmp_path / "terraform"
    target_dir.mkdir()
    target_file = target_dir / "security-groups.tf"
    target_file.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    decision = plan_from_terraform(
        finding=public_ssh_finding(),
        terraform_root=target_dir,
        replacement_source="203.0.113.10/32",
    )
    patch = generate_standalone_public_ssh_patch(decision)
    broken_patch = type(patch)(
        file_path=patch.file_path,
        before=patch.before,
        after=patch.before,
        resource_address=patch.resource_address,
        summary=patch.summary,
        diff=patch.diff,
    )
    validation = validate_public_ssh_patch(broken_patch)

    assert validation.passed is False
    assert "patched content still contains a public SSH source" in validation.errors
