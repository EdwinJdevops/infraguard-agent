from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from infraguard.policy import PolicyError, validate_replacement_source


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    api_key: str | None
    terraform_root: Path | None
    terraform_state_path: Path | None = None
    allowed_ssh_cidrs: tuple[str, ...] = ()
    environment: str = "development"
    docs_enabled: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        root_value = os.getenv("INFRAGUARD_TERRAFORM_ROOT")
        state_value = os.getenv("INFRAGUARD_TERRAFORM_STATE_PATH")
        allowed_ssh_cidrs = tuple(
            value.strip()
            for value in os.getenv("INFRAGUARD_ALLOWED_SSH_CIDRS", "").split(",")
            if value.strip()
        )
        return cls(
            api_key=os.getenv("INFRAGUARD_API_KEY"),
            terraform_root=Path(root_value).resolve() if root_value else None,
            terraform_state_path=Path(state_value).resolve() if state_value else None,
            allowed_ssh_cidrs=allowed_ssh_cidrs,
            environment=os.getenv("INFRAGUARD_ENVIRONMENT", "development"),
            docs_enabled=_env_bool("INFRAGUARD_DOCS_ENABLED"),
        )

    def readiness_errors(self) -> list[str]:
        errors: list[str] = []
        if not self.api_key:
            errors.append("INFRAGUARD_API_KEY is not configured")
        if self.api_key and len(self.api_key) < 32:
            errors.append("INFRAGUARD_API_KEY must contain at least 32 characters")
        if self.terraform_root is None:
            errors.append("INFRAGUARD_TERRAFORM_ROOT is not configured")
        elif not self.terraform_root.is_dir():
            errors.append("INFRAGUARD_TERRAFORM_ROOT is not a directory")
        if self.terraform_state_path is not None and not self.terraform_state_path.is_file():
            errors.append("INFRAGUARD_TERRAFORM_STATE_PATH is not a file")
        if not self.allowed_ssh_cidrs:
            errors.append("INFRAGUARD_ALLOWED_SSH_CIDRS is not configured")
        for source in self.allowed_ssh_cidrs:
            try:
                validate_replacement_source(source)
            except PolicyError:
                errors.append("INFRAGUARD_ALLOWED_SSH_CIDRS contains an invalid source")
        return errors
