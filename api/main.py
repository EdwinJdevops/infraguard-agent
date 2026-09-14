from __future__ import annotations

import logging
import secrets
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from api.config import Settings
from api.schemas import (
    PatchResponse,
    RemediationPlanRequest,
    RemediationPlanResponse,
    TerraformResourceResponse,
    ValidationResponse,
)
from infraguard.ownership import OwnershipError
from infraguard.patches import PatchError
from infraguard.runbook import run_public_ssh_remediation

LOGGER = logging.getLogger("infraguard.api")
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or Settings.from_env()
    app_limiter = Limiter(key_func=get_remote_address)
    docs_url = "/docs" if app_settings.docs_enabled else None
    app = FastAPI(
        title="InfraGuard",
        description=(
            "Evidence-based GitOps remediation planning for Terraform-managed cloud findings."
        ),
        version="0.2.0",
        docs_url=docs_url,
        redoc_url=None,
        openapi_url="/openapi.json" if app_settings.docs_enabled else None,
    )
    app.state.settings = app_settings
    app.state.limiter = app_limiter

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid4())
        request.state.request_id = request_id[:128]
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        del exc
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "rate limit exceeded", "request_id": request.state.request_id},
        )

    @app.exception_handler(OwnershipError)
    @app.exception_handler(PatchError)
    async def remediation_evidence_handler(request: Request, exc: ValueError):
        LOGGER.warning(
            "remediation evidence rejected request_id=%s error=%s",
            request.state.request_id,
            exc,
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={
                "detail": "Terraform evidence could not produce a safe remediation plan",
                "request_id": request.state.request_id,
            },
        )

    @app.get("/")
    async def root() -> dict[str, object]:
        return {
            "service": "InfraGuard",
            "version": "0.2.0",
            "capability": "aws_public_ssh_terraform_remediation_planning",
            "publication": "not_implemented",
        }

    @app.get("/livez")
    async def liveness() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/readyz")
    @app.get("/health")
    async def readiness(request: Request) -> JSONResponse:
        errors = request.app.state.settings.readiness_errors()
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE if errors else status.HTTP_200_OK,
            content={"status": "not_ready" if errors else "ready", "checks": errors},
        )

    @app.post(
        "/v1/remediation-plans",
        response_model=RemediationPlanResponse,
        status_code=status.HTTP_200_OK,
    )
    @app_limiter.limit("5/minute")
    async def create_remediation_plan(
        request: Request,
        payload: RemediationPlanRequest,
        _: str = Depends(verify_api_key),
    ) -> RemediationPlanResponse:
        settings = request.app.state.settings
        if settings.readiness_errors():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="service is not configured for remediation planning",
            )
        run = run_public_ssh_remediation(
            finding=payload.to_finding(),
            terraform_root=settings.terraform_root,
            replacement_source=payload.replacement_source,
            terraform_state_path=settings.terraform_state_path,
            allowed_replacement_sources=settings.allowed_ssh_cidrs,
        )
        return _response_from_run(run, settings.terraform_root)

    @app.post("/remediate", status_code=status.HTTP_410_GONE)
    async def retired_remediation_endpoint(_: str = Depends(verify_api_key)) -> dict[str, str]:
        return {
            "detail": "unsafe legacy remediation is retired; use POST /v1/remediation-plans",
        }

    return app


async def verify_api_key(request: Request, api_key: str | None = Depends(API_KEY_HEADER)) -> str:
    expected = request.app.state.settings.api_key
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured",
        )
    if api_key is None or not secrets.compare_digest(api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key


def _response_from_run(run, terraform_root: Path) -> RemediationPlanResponse:
    resource = run.decision.terraform_resource
    relative_file = None
    if resource and resource.file_path:
        relative_file = _relative_path(resource.file_path, terraform_root)
    patch_response = None
    validation_response = None
    evidence_bundle = None
    if run.patch:
        patch_diff = _redact_absolute_path(run.patch.diff, run.patch.file_path, relative_file)
        patch_response = PatchResponse(
            file_path=relative_file or "unknown",
            resource_address=run.patch.resource_address,
            summary=run.patch.summary,
            diff=patch_diff,
        )
    if run.validation:
        validation_response = ValidationResponse(**run.validation.to_evidence())
    if run.evidence_json:
        evidence_bundle = deepcopy(run.evidence_json)
        terraform_resource = evidence_bundle.get("terraform_resource")
        if isinstance(terraform_resource, dict):
            terraform_resource["file_path"] = relative_file
        patch = evidence_bundle.get("patch")
        if isinstance(patch, dict):
            patch["file_path"] = relative_file
            if run.patch:
                patch["diff"] = _redact_absolute_path(
                    str(patch.get("diff", "")), run.patch.file_path, relative_file
                )

    return RemediationPlanResponse(
        alert_id=run.decision.finding.alert_id,
        decision=run.decision.decision.value,
        reason=run.decision.reason,
        ownership=run.decision.ownership.value,
        can_open_pr=run.can_open_pr,
        decision_evidence=run.decision.evidence,
        terraform_resource=(
            TerraformResourceResponse(
                address=resource.address,
                file_path=relative_file or "unknown",
            )
            if resource
            else None
        ),
        patch=patch_response,
        validation=validation_response,
        evidence_bundle=evidence_bundle,
        pr_body=(
            _redact_absolute_path(run.pr_markdown, run.patch.file_path, relative_file)
            if run.pr_markdown and run.patch
            else run.pr_markdown
        ),
    )


def _relative_path(file_path: str, terraform_root: Path) -> str:
    return Path(file_path).resolve().relative_to(terraform_root.resolve()).as_posix()


def _redact_absolute_path(diff: str, absolute_path: str, relative_path: str | None) -> str:
    return diff.replace(absolute_path, relative_path or "unknown")


app = create_app()
