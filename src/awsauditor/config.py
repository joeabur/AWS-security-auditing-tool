"""Audit configuration (TOML). Credentials are deliberately not representable here."""

from __future__ import annotations

import tomllib
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .errors import ConfigError
from .models import Severity

_SECRET_KEYS = {
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "access_key",
    "secret_key",
    "secret_access_key",
    "session_token",
    "password",
    "external_id",
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


REPORT_FORMATS = ("json", "csv", "html", "sarif")


class Suppression(_Strict):
    """An explicit, expiring acceptance of a FAIL finding. Never hides it from reports."""

    control_id: str = Field(pattern=r"^[A-Z]{2,4}-\d{3}$")
    resource: str = "*"  # fnmatch pattern against the finding's resource_id
    region: str = "*"  # fnmatch pattern against the finding's region
    reason: str = Field(min_length=10)
    owner: str = Field(min_length=3)
    expires: date


class ProfileSpec(_Strict):
    """A named selection of controls."""

    services: list[str] = Field(default_factory=list)
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    min_severity: Severity | None = None


BUILTIN_PROFILES: dict[str, ProfileSpec] = {
    "full": ProfileSpec(),
    "baseline": ProfileSpec(min_severity=Severity.HIGH),
}


class AwsSettings(_Strict):
    profile: str | None = None  # name of a shared-config profile, not a secret
    role_arn: str | None = None
    role_session_name: str = "aws-security-auditing-tool"
    role_duration_seconds: int = Field(default=3600, ge=900, le=43200)
    home_region: str | None = None
    max_attempts: int = Field(default=8, ge=1, le=20)
    connect_timeout: int = Field(default=10, ge=1, le=120)
    read_timeout: int = Field(default=60, ge=1, le=600)

    @field_validator("role_arn")
    @classmethod
    def _role_arn(cls, v: str | None) -> str | None:
        if v is not None and not v.startswith("arn:"):
            raise ValueError("role_arn must be an IAM role ARN")
        return v


class AuditSettings(_Strict):
    profile: str = "baseline"
    regions: list[str] = Field(default_factory=list)  # empty or ["all"] = all enabled regions
    workers: int = Field(default=4, ge=1, le=16)


class Thresholds(_Strict):
    unused_credential_days: int = Field(default=45, ge=1)
    access_key_max_age_days: int = Field(default=90, ge=1)
    password_min_length: int = Field(default=14, ge=6, le=128)
    password_reuse_prevention: int = Field(default=24, ge=1, le=24)
    log_retention_min_days: int = Field(default=365, ge=1)
    sensitive_ports: list[int] = Field(
        default_factory=lambda: [
            21,
            22,
            23,
            445,
            1433,
            1521,
            2049,
            3306,
            3389,
            5432,
            5900,
            6379,
            9200,
            11211,
            27017,
        ]
    )

    @field_validator("sensitive_ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(p < 0 or p > 65535 for p in v):
            raise ValueError("ports must be within 0-65535")
        return sorted(set(v))


class RedactionSettings(_Strict):
    enabled: bool = False
    account_ids: bool = True
    access_key_ids: bool = True
    ip_addresses: bool = False


class OutputSettings(_Strict):
    directory: Path = Path("audit-output")
    formats: list[str] = Field(default_factory=lambda: ["json"])

    @field_validator("formats")
    @classmethod
    def _formats(cls, v: list[str]) -> list[str]:
        bad = set(v) - set(REPORT_FORMATS)
        if bad:
            raise ValueError(f"unsupported formats: {sorted(bad)}")
        return v


class AuditConfig(_Strict):
    aws: AwsSettings = Field(default_factory=AwsSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    redaction: RedactionSettings = Field(default_factory=RedactionSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    profiles: dict[str, ProfileSpec] = Field(default_factory=dict)
    suppressions: list[Suppression] = Field(default_factory=list)

    @model_validator(mode="after")
    def _profile_exists(self) -> AuditConfig:
        if self.audit.profile not in self.all_profiles():
            raise ValueError(f"audit.profile '{self.audit.profile}' is not defined")
        return self

    def all_profiles(self) -> dict[str, ProfileSpec]:
        return {**BUILTIN_PROFILES, **self.profiles}


def _find_secret_keys(data: Any, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            here = f"{path}.{k}" if path else str(k)
            if str(k).lower() in _SECRET_KEYS:
                hits.append(here)
            hits.extend(_find_secret_keys(v, here))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            hits.extend(_find_secret_keys(item, f"{path}[{i}]"))
    return hits


def parse_config(data: dict[str, Any]) -> AuditConfig:
    secrets = _find_secret_keys(data)
    if secrets:
        raise ConfigError(
            "credentials must not be stored in configuration files (found: "
            + ", ".join(secrets)
            + "). Use the standard AWS credential chain, SSO, or role assumption."
        )
    try:
        return AuditConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration: {exc}") from exc


def load_config(path: Path | None) -> AuditConfig:
    if path is None:
        return AuditConfig()
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read configuration {path}: {exc}") from exc
    return parse_config(data)
