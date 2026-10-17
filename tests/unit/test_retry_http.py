"""Verify retry/backoff against a real (localhost) HTTP endpoint - no AWS is contacted.

Stubber short-circuits the HTTP layer, so it cannot show that botocore actually retries
throttled calls. This test points a client built from the production ClientFactory config
at a local server that always answers with an IAM `Throttling` error.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from awsauditor.errors import classify_exception
from awsauditor.models import Status
from awsauditor.session import ClientFactory

BODY = (
    b'<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error>'
    b"<Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error>"
    b"<RequestId>req-1</RequestId></ErrorResponse>"
)


class _Handler(BaseHTTPRequestHandler):
    hits = 0

    def do_POST(self) -> None:
        type(self).hits += 1
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(400)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args: Any) -> None:  # keep test output quiet
        return


@pytest.fixture
def server() -> Any:
    _Handler.hits = 0
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def test_throttling_is_retried_then_reported_as_error(server: Any) -> None:
    session = boto3.Session(
        aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1"
    )
    factory = ClientFactory(session, max_attempts=3, connect_timeout=2, read_timeout=2)
    client = session.client(
        "iam", endpoint_url=f"http://127.0.0.1:{server.server_port}", config=factory._config
    )
    client.meta.events.register("before-parameter-build.*.*", factory._guard)
    with pytest.raises(ClientError) as info:
        client.get_account_summary()
    assert _Handler.hits == 3  # one attempt plus two retries, then give up
    status, message, _ = classify_exception(info.value)
    assert status is Status.ERROR and "throttled" in message
    assert factory.oplog.snapshot() == {"iam:GetAccountSummary": 1}  # logged once, not per retry
