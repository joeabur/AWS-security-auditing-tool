"""Exception types and classification of AWS errors into finding statuses."""

from __future__ import annotations

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    CredentialRetrievalError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
    ReadTimeoutError,
)

from .models import Status


class AuditorError(Exception):
    """Base class for auditor-specific errors."""


class ConfigError(AuditorError):
    """Invalid configuration."""


class ReadOnlyViolation(AuditorError):
    """Raised when code attempts an AWS operation outside the read-only allowlist."""


class ParseError(AuditorError):
    """An AWS response was missing expected fields or malformed."""


class AccountMismatch(AuditorError):
    """The resolved account does not match what the operator confirmed."""


ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnauthorizedAccess",
        "AuthorizationError",
        "AccessDeniedFault",
        "403",
    }
)
THROTTLE_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "RequestThrottled",
        "SlowDown",
        "ProvisionedThroughputExceededException",
    }
)
EXPIRED_CODES = frozenset({"ExpiredToken", "ExpiredTokenException", "RequestExpired"})
# Region not enabled / service not offered / endpoint unreachable: the control could not be
# evaluated there, but that is not a permissions or code problem.
UNSUPPORTED_CODES = frozenset(
    {
        "OptInRequired",
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "UnsupportedOperation",
        "AuthFailure",
        "SubscriptionRequiredException",
    }
)


def classify_exception(exc: BaseException) -> tuple[Status, str, str]:
    """Map an exception to ``(status, message, uncertainty)``.

    Never returns PASS: an error is never evidence of compliance.
    """
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = str(err.get("Code", "Unknown"))
        op = exc.operation_name
        if code in ACCESS_DENIED_CODES:
            return (
                Status.ERROR,
                f"Permission denied calling {op}.",
                "Grant the missing read-only permission (see policies/) and re-run; "
                "the control result is unknown.",
            )
        if code in EXPIRED_CODES:
            return (
                Status.ERROR,
                f"AWS credentials expired while calling {op}.",
                "Re-authenticate (assumed-role sessions last at most role_duration_seconds) "
                "and re-run; the control result is unknown.",
            )
        if code in THROTTLE_CODES:
            return (
                Status.ERROR,
                f"AWS throttled {op} and retries were exhausted.",
                "Re-run with fewer workers or a higher retry limit; the control result is unknown.",
            )
        if code in UNSUPPORTED_CODES:
            return (
                Status.NOT_ASSESSED,
                f"{op} is not available in this region or for this account ({code}).",
                "The region may be disabled, opt-in, or lack the service; state is unknown.",
            )
        return (
            Status.ERROR,
            f"AWS returned error {code} for {op}.",
            "The control result is unknown.",
        )
    if isinstance(exc, EndpointConnectionError):
        return (
            Status.NOT_ASSESSED,
            "No service endpoint reachable in this region.",
            "The service may not exist in this region, or the network blocked the request.",
        )
    if isinstance(exc, ConnectTimeoutError | ReadTimeoutError):
        return Status.ERROR, "Timed out calling AWS.", "The control result is unknown."
    if isinstance(exc, NoCredentialsError | PartialCredentialsError | CredentialRetrievalError):
        return (
            Status.ERROR,
            "AWS credentials are missing or unusable.",
            "Check the credential chain (SSO login, profile, role); the control result is unknown.",
        )
    if isinstance(exc, ReadOnlyViolation):
        return Status.ERROR, str(exc), "Internal read-only guard rejected the call."
    if isinstance(exc, ParseError | KeyError | TypeError | ValueError | AttributeError):
        return (
            Status.ERROR,
            f"Malformed or unexpected AWS response: {type(exc).__name__}.",
            "The control result is unknown.",
        )
    if isinstance(exc, BotoCoreError):
        return Status.ERROR, f"AWS client error: {type(exc).__name__}.", "Result unknown."
    return Status.ERROR, f"Unexpected error: {type(exc).__name__}.", "Result unknown."
