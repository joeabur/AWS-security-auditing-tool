"""Configurable redaction of sensitive identifiers in reports."""

from __future__ import annotations

import re
from typing import Any

from .config import RedactionSettings

_ACCOUNT = re.compile(r"(?<!\d)(\d{8})(\d{4})(?!\d)")
_ACCESS_KEY = re.compile(
    r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|APKA)[A-Z0-9]{4})[A-Z0-9]{12}\b"
)
_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


class Redactor:
    def __init__(self, settings: RedactionSettings) -> None:
        self._s = settings

    def text(self, value: str) -> str:
        if not self._s.enabled:
            return value
        if self._s.account_ids:
            value = _ACCOUNT.sub(lambda m: "********" + m.group(2), value)
        if self._s.access_key_ids:
            value = _ACCESS_KEY.sub(lambda m: m.group(1) + "************", value)
        if self._s.ip_addresses:
            value = _IPV4.sub(_mask_ip, value)
        return value

    def apply(self, data: Any) -> Any:
        """Return a deep copy of JSON-like ``data`` with strings redacted."""
        if not self._s.enabled:
            return data
        if isinstance(data, str):
            return self.text(data)
        if isinstance(data, list):
            return [self.apply(v) for v in data]
        if isinstance(data, dict):
            return {k: self.apply(v) for k, v in data.items()}
        return data


def _mask_ip(match: re.Match[str]) -> str:
    """Mask the host part of an IPv4 address; keep the all-zeros 'whole internet' CIDR."""
    if match.group(0) == "0.0.0.0":  # noqa: S104 - literal match, not a bind
        return match.group(0)
    return f"{match.group(1)}.x.x.x"
