from pathlib import Path

from fastapi.testclient import TestClient

from api.config import Settings
from api.main import create_app

FIXTURES = Path(__file__).parent / "fixtures" / "terraform"
API_KEY = "test-api-key-with-at-least-32-characters"


def payload(**overrides) -> dict:
    value = {
        "alert_id": "alert-001",
        "provider": "aws",
        "account_id": "123456789012",
        "region": "us-east-1",
        "resource_type": "aws_security_group",
        "resource_id": "sg-1234567890abcdef0",
        "rule": {
            "direction": "ingress",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "source": "0.0.0.0/0",
        },
        "replacement_source": "10.20.30.40/32",
    }
    value.update(overrides)
    return value


def client(terraform_root: Path | None, api_key: str | None = API_KEY) -> TestClient:
    return TestClient(
        create_app(
            Settings(
                api_key=api_key,
                terraform_root=terraform_root,
                allowed_ssh_cidrs=("10.20.30.40/32",),
            )
        )
    )


def test_readiness_fails_closed_when_configuration_is_missing() -> None:
    response = client(None, api_key=None).get("/readyz")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert len(response.json()["checks"]) == 2


def test_readiness_rejects_invalid_allowed_source() -> None:
    app = create_app(
        Settings(
            api_key=API_KEY,
            terraform_root=FIXTURES / "standalone_public_ssh",
            allowed_ssh_cidrs=("8.8.8.8/32",),
        )
    )

    response = TestClient(app).get("/readyz")

    assert response.status_code == 503
    assert response.json()["checks"] == [
        "INFRAGUARD_ALLOWED_SSH_CIDRS contains an invalid source"
    ]


def test_remediation_plan_requires_authentication() -> None:
    response = client(FIXTURES / "standalone_public_ssh").post(
        "/v1/remediation-plans", json=payload()
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid or missing API key"


def test_unverified_api_claim_cannot_produce_patch_or_publication() -> None:
    terraform_root = (FIXTURES / "standalone_public_ssh").resolve()
    target_file = terraform_root / "security-groups.tf"
    source_before = target_file.read_text(encoding="utf-8")
    response = client(terraform_root).post(
        "/v1/remediation-plans",
        headers={"X-API-Key": API_KEY, "X-Request-ID": "request-123"},
        json=payload(),
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "request-123"
    body = response.json()
    assert body["decision"] == "manual_review"
    assert body["can_open_pr"] is False
    assert body["publication"] == "not_attempted"
    assert body["patch"] is None
    assert body["validation"] is None
    assert body["evidence_bundle"] is None
    assert body["pr_body"] is None
    assert "independent live AWS rule verification" in body["reason"]
    assert str(terraform_root) not in response.text
    assert target_file.read_text(encoding="utf-8") == source_before


def test_unknown_ownership_returns_manual_review_without_patch() -> None:
    response = client(FIXTURES / "no_public_ssh").post(
        "/v1/remediation-plans",
        headers={"X-API-Key": API_KEY},
        json=payload(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "manual_review"
    assert body["can_open_pr"] is False
    assert body["patch"] is None
    assert body["publication"] == "not_attempted"


def test_unverified_api_claim_is_stopped_before_replacement_policy() -> None:
    response = client(FIXTURES / "standalone_public_ssh").post(
        "/v1/remediation-plans",
        headers={"X-API-Key": API_KEY},
        json=payload(replacement_source="10.99.0.0/16"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "manual_review"
    assert body["can_open_pr"] is False
    assert "independent live AWS rule verification" in body["reason"]


def test_invalid_payload_is_rejected_before_planning() -> None:
    response = client(FIXTURES / "standalone_public_ssh").post(
        "/v1/remediation-plans",
        headers={"X-API-Key": API_KEY},
        json=payload(account_id="production", unexpected=True),
    )

    assert response.status_code == 422


def test_unverified_api_claim_does_not_parse_terraform(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_security_group" "broken" {', encoding="utf-8")
    response = client(tmp_path).post(
        "/v1/remediation-plans",
        headers={"X-API-Key": API_KEY},
        json=payload(),
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "manual_review"
    assert response.json()["patch"] is None
    assert str(tmp_path) not in response.text


def test_legacy_remediation_endpoint_is_retired() -> None:
    response = client(FIXTURES / "standalone_public_ssh").post(
        "/remediate", headers={"X-API-Key": API_KEY}
    )

    assert response.status_code == 410
    assert "retired" in response.json()["detail"]
