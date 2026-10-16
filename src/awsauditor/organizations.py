"""Optional AWS Organizations discovery (separate permissions; lists accounts only)."""

from __future__ import annotations

from dataclasses import dataclass

from .evidence import paginate, require
from .session import ClientFactory

ORG_ACTIONS = ["organizations:DescribeOrganization", "organizations:ListAccounts"]


@dataclass(frozen=True)
class OrgAccount:
    account_id: str
    name: str
    status: str


def list_accounts(factory: ClientFactory, region: str) -> list[OrgAccount]:
    client = factory.client("organizations", region)
    require(client.describe_organization(), "Organization", dict)
    return [
        OrgAccount(require(a, "Id", str), str(a.get("Name", "")), str(a.get("Status", "UNKNOWN")))
        for a in paginate(client, "list_accounts", "Accounts")
    ]
