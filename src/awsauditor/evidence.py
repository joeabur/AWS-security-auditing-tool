"""Evidence collection helpers: pagination and strict response validation."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, TypeVar

from .errors import ParseError

T = TypeVar("T")


def require(container: Any, key: str, expected: type[T]) -> T:
    """Return ``container[key]`` or raise ParseError if absent or of the wrong type."""
    if not isinstance(container, dict) or key not in container:
        raise ParseError(f"missing field '{key}'")
    value = container[key]
    if not isinstance(value, expected):
        raise ParseError(f"field '{key}' has unexpected type {type(value).__name__}")
    return value


def optional(container: Any, key: str, expected: type[T]) -> T | None:
    """Return ``container[key]`` if present, validating its type; None if absent."""
    if not isinstance(container, dict):
        raise ParseError("expected an object")
    if key not in container or container[key] is None:
        return None
    value = container[key]
    if not isinstance(value, expected):
        raise ParseError(f"field '{key}' has unexpected type {type(value).__name__}")
    return value


def paginate(
    client: Any, operation: str, result_key: str, **kwargs: Any
) -> Iterator[dict[str, Any]]:
    """Yield every item of ``result_key`` across all pages of a paginated operation."""
    if not client.can_paginate(operation):
        raise ParseError(f"operation {operation} is not paginatable")
    for page in client.get_paginator(operation).paginate(**kwargs):
        items = page.get(result_key, [])
        if not isinstance(items, list):
            raise ParseError(f"field '{result_key}' is not a list")
        for item in items:
            if not isinstance(item, dict):
                raise ParseError(f"item in '{result_key}' is not an object")
            yield item


def paginate_scalars(client: Any, operation: str, result_key: str, **kwargs: Any) -> Iterator[Any]:
    """Like :func:`paginate` for operations returning lists of strings."""
    if not client.can_paginate(operation):
        raise ParseError(f"operation {operation} is not paginatable")
    for page in client.get_paginator(operation).paginate(**kwargs):
        items = page.get(result_key, [])
        if not isinstance(items, list):
            raise ParseError(f"field '{result_key}' is not a list")
        yield from items


def error_code(exc: BaseException) -> str:
    """The AWS error code of a ClientError, or '' for anything else."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""
