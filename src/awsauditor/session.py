"""AWS session management: credential chain, role assumption, read-only client factory."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from . import __version__
from .errors import AuditorError, ReadOnlyViolation

# Operations allowed through the guard. Anything else is rejected before a request is built.
_READ_PREFIXES = ("Get", "List", "Describe")
# Explicit exceptions: GenerateCredentialReport asks IAM to (re)build the credential report. It
# creates no customer resource and is the documented prerequisite for GetCredentialReport.
_EXTRA_ALLOWED = frozenset({"GenerateCredentialReport"})

# boto3 service name -> IAM action prefix, where they differ.
_IAM_PREFIX = {"accessanalyzer": "access-analyzer", "logs": "logs", "s3control": "s3"}
# (service, operation) -> IAM action, where the action name differs from the operation name.
_IAM_ACTION_OVERRIDES = {
    ("s3", "ListBuckets"): "s3:ListAllMyBuckets",
    ("s3", "GetBucketEncryption"): "s3:GetEncryptionConfiguration",
    ("s3", "GetPublicAccessBlock"): "s3:GetBucketPublicAccessBlock",
    ("s3control", "GetPublicAccessBlock"): "s3:GetAccountPublicAccessBlock",
    ("sts", "GetCallerIdentity"): "",  # requires no permission
}


def iam_action_for(service: str, operation: str) -> str:
    """Return the IAM action authorizing a boto3 operation ('' if none is required)."""
    override = _IAM_ACTION_OVERRIDES.get((service, operation))
    if override is not None:
        return override
    return f"{_IAM_PREFIX.get(service, service)}:{operation}"


def is_read_only_operation(operation: str) -> bool:
    return operation.startswith(_READ_PREFIXES) or operation in _EXTRA_ALLOWED


@dataclass
class OperationLog:
    """Thread-safe record of IAM actions actually exercised (never request/response bodies)."""

    _actions: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, action: str) -> None:
        with self._lock:
            self._actions[action] = self._actions.get(action, 0) + 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(sorted(self._actions.items()))


@dataclass(frozen=True)
class Identity:
    account_id: str
    arn: str
    partition: str


class ClientFactory:
    """Creates and caches boto3 clients with retry config and the read-only guard attached."""

    def __init__(
        self,
        session: boto3.Session,
        *,
        max_attempts: int = 8,
        connect_timeout: int = 10,
        read_timeout: int = 60,
        oplog: OperationLog | None = None,
    ) -> None:
        self._session = session
        self._config = Config(
            retries={"mode": "adaptive", "max_attempts": max_attempts},
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            user_agent_extra=f"aws-security-auditing-tool/{__version__}",
        )
        self._cache: dict[tuple[str, str | None], Any] = {}
        self._lock = threading.Lock()
        self.oplog = oplog or OperationLog()

    def client(self, service: str, region: str | None = None) -> Any:
        key = (service, region)
        with self._lock:
            if key not in self._cache:
                client = self._session.client(service, region_name=region, config=self._config)
                client.meta.events.register("before-parameter-build.*.*", self._guard)
                self._cache[key] = client
            return self._cache[key]

    def _guard(self, model: Any, **_kwargs: Any) -> None:
        operation = model.name
        service = model.service_model.service_name
        if not is_read_only_operation(operation):
            raise ReadOnlyViolation(f"blocked non-read-only operation {service}:{operation}")
        action = iam_action_for(service, operation)
        if action:
            self.oplog.record(action)

    @property
    def default_region(self) -> str | None:
        region = self._session.region_name
        return str(region) if region else None

    @property
    def available_partition_regions(self) -> Callable[[str, str], list[str]]:
        return lambda service, partition: list(
            self._session.get_available_regions(service, partition_name=partition)
        )


def build_session(
    profile: str | None,
    role_arn: str | None,
    role_session_name: str,
    duration_seconds: int,
    external_id: str | None = None,
) -> boto3.Session:
    """Create a boto3 session from the standard credential chain, optionally assuming a role.

    ``external_id`` is accepted only from the caller (the CLI reads it from the environment,
    never from arguments or files).
    """
    base = boto3.Session(profile_name=profile)
    if not role_arn:
        return base
    sts = base.client("sts")
    params: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": role_session_name,
        "DurationSeconds": duration_seconds,
    }
    if external_id:
        params["ExternalId"] = external_id
    try:
        creds = sts.assume_role(**params)["Credentials"]
    except (ClientError, BotoCoreError, KeyError) as exc:
        raise AuditorError(f"could not assume role: {type(exc).__name__}") from exc
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=base.region_name,
    )


def resolve_identity(factory: ClientFactory, region: str | None = None) -> Identity:
    """Resolve the caller identity (sts:GetCallerIdentity, which needs no permission)."""
    try:
        resp = factory.client("sts", region).get_caller_identity()
        arn = str(resp["Arn"])
        return Identity(account_id=str(resp["Account"]), arn=arn, partition=arn.split(":")[1])
    except (ClientError, BotoCoreError, KeyError, IndexError) as exc:
        raise AuditorError(
            f"could not resolve AWS identity ({type(exc).__name__}); check credentials"
        ) from exc
