# Threat model

## Assets

1. The audited AWS accounts (must not be altered).
2. Credentials used by the auditor (must not leak).
3. Audit reports: they enumerate misconfigurations, i.e. a map for an attacker.
4. The integrity of the results (a wrong PASS is worse than a missing result).

## Trust boundaries

- Operator workstation or CI runner → AWS APIs (TLS, SigV4, via boto3).
- AWS API responses → parser. Resource names, tags, descriptions and error messages are
  attacker-influenced strings in an account the operator may not fully trust.
- Report files → viewers (browsers, spreadsheets).

## Threats and mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | Bug or malicious change makes the tool mutate resources | `ClientFactory` guard raises `ReadOnlyViolation` for any operation outside `Get*/List*/Describe*` + `GenerateCredentialReport`; tests prove representative mutating calls are blocked; the IAM policy grants no write actions; no remediation code exists | The guard trusts operation names; IAM policy is the second, independent layer — always use it |
| T2 | Credentials leak via arguments, config, logs or reports | No CLI option or config key accepts a secret (config parser rejects such keys); credentials come from the boto3 chain / SSO / role assumption; external ID only via environment; logs omit request/response bodies; reports hold no key material | Credentials in the operator's own environment/shell history are outside the tool |
| T3 | Auditing the wrong account | Resolved account ID and regions are printed; explicit confirmation (`--confirm-account` or typed prompt) required; mismatch aborts before any audit API call (tested) | Operator may confirm the wrong ID deliberately |
| T4 | API error treated as compliance (false PASS) | All errors classify to ERROR/NOT_ASSESSED; resilience tests inject AccessDenied, throttling, 5xx and opt-in errors into **every** check and assert no PASS | Logic errors in a check's criteria remain possible; see unit tests per control |
| T5 | Malformed/hostile response data (injection into reports) | HTML output escapes all values and sets a restrictive CSP; CSV neutralizes formula prefixes (`= + - @`); JSON via serializer | Consumers re-rendering JSON must escape it themselves |
| T6 | Report disclosure | Reports written with mode `0600` in a `0700` directory; no overwrite without `--force`; optional redaction of account IDs, access key IDs, IPs; evidence deliberately excludes policy documents, descriptions, tags, KMS key ARNs | Reports still describe weaknesses; store and transmit them as sensitive |
| T7 | Over-privileged auditor | Least-privilege policy generated from the catalog and tested for equality with the APIs actually called; administrator access never required | `Resource: "*"` is inherent to these APIs |
| T8 | Throttling or cost impact on production | Adaptive retries, worker limit (default 4), read-only list/describe calls only | Large accounts take longer; no cost is incurred by the APIs used |
| T9 | Supply-chain compromise | Lockfile (`uv.lock`), `pip-audit` and secret scanning in CI, GitHub Actions pinned to commit SHAs, `permissions: contents: read` | Transitive dependencies are trusted after audit |
| T10 | Stale evidence | Every finding has `observed_at`; reports are point-in-time | Configuration may change right after the audit |

## Out of scope

Detection of an already-compromised account, runtime/workload vulnerabilities, data-plane
content inspection, and compliance certification.
