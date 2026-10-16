# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, using GitHub's **Report a vulnerability**
(private security advisory) on this repository, or email markjoejay1960@gmail.com. Do not open
a public issue with exploit details. Expect an acknowledgement within a few days; this is a
personal open-source project without an SLA.

In scope: anything that could let the tool modify AWS resources, leak credentials or sensitive
report data, bypass the account-confirmation step, report PASS where the evidence is unknown,
or allow injection via report output (HTML/CSV).

## Security properties this project aims to maintain

- Read-only: only `Get*`, `List*`, `Describe*` and `GenerateCredentialReport` operations are
  possible; the client guard rejects everything else. No auto-remediation.
- No secrets accepted via arguments or configuration files; credentials come from the standard
  boto3 chain, SSO or role assumption.
- Errors are never treated as passing.
- Reports are written `0600`; redaction is available for account IDs, access key IDs and IPs.

## Handling audit reports

Reports describe your weaknesses. Treat them as confidential: keep them out of public
repositories and tickets, and use `--redact` before sharing.

## Supported versions

Only the latest release/`main` receives fixes.
