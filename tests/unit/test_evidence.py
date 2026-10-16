"""Strict response validation helpers."""

from __future__ import annotations

import pytest

from awsauditor.errors import ParseError
from awsauditor.evidence import error_code, optional, paginate, paginate_scalars, require

from .conftest import Harness, error_payload


def test_require_and_optional() -> None:
    assert require({"a": [1]}, "a", list) == [1]
    for bad in (None, [], {"a": 1}, {}):
        with pytest.raises(ParseError):
            require(bad, "a", list)
    assert optional({"a": None}, "a", str) is None
    assert optional({}, "a", str) is None
    assert optional({"a": "x"}, "a", str) == "x"
    with pytest.raises(ParseError):
        optional({"a": 1}, "a", str)
    with pytest.raises(ParseError):
        optional([], "a", str)


def test_paginate_rejects_malformed_pages() -> None:
    h = Harness()
    h.factory.fault = {"status": 200, "parsed": {"Volumes": "not-a-list"}}
    with pytest.raises(ParseError, match="not a list"):
        list(paginate(h.factory.client("ec2", "us-east-1"), "describe_volumes", "Volumes"))
    h.factory.fault = {"status": 200, "parsed": {"Volumes": ["str"]}}
    with pytest.raises(ParseError, match="not an object"):
        list(paginate(h.factory.client("ec2", "us-east-1"), "describe_volumes", "Volumes"))
    h.factory.fault = {"status": 200, "parsed": {"DetectorIds": "x"}}
    with pytest.raises(ParseError):
        list(
            paginate_scalars(
                h.factory.client("guardduty", "us-east-1"), "list_detectors", "DetectorIds"
            )
        )


def test_paginate_requires_a_paginator() -> None:
    h = Harness()
    client = h.factory.client("cloudwatch", "us-east-1")
    with pytest.raises(ParseError, match="not paginatable"):
        list(paginate(client, "describe_alarms_for_metric", "MetricAlarms"))
    with pytest.raises(ParseError, match="not paginatable"):
        list(paginate_scalars(client, "describe_alarms_for_metric", "MetricAlarms"))


def test_error_code() -> None:
    from botocore.exceptions import ClientError

    assert error_code(ClientError({"Error": {"Code": "X", "Message": "m"}}, "Op")) == "X"
    assert error_code(ValueError("x")) == ""
    assert error_payload("Y")["parsed"]["Error"]["Code"] == "Y"
