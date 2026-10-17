# Architecture

```
            CLI (cli.py, Typer)
                 │  config.py (TOML → pydantic, rejects credentials)
                 ▼
 session.py ── ClientFactory ── read-only guard + retry config + operation log
     │              ▲
     │ identity     │ clients
     ▼              │
 regions.py ──► runner.py ──► checks/*.py ──► evidence.py (pagination, strict parsing)
 (discovery)    (scheduling,      │ context.py (CheckContext, SharedCache, registry)
                 partial results) ▼
                              models.Finding
                                  │
                       reporting/ (model, JSON, CSV, HTML, files) + redaction.py
```

| Module | Responsibility |
|---|---|
| `session.py` | Boto3 credential chain, optional `sts:AssumeRole`, client cache, **read-only guard** (rejects any operation not named `Get*/List*/Describe*` or `GenerateCredentialReport` *before* a request is built), adaptive retry/backoff config, thread-safe record of IAM actions actually used. |
| `regions.py` | `ec2:DescribeRegions` discovery of enabled regions, validation of requested regions, explicit degraded mode (with a warning) when discovery is denied. |
| `catalog.py`, `controls/catalog.json` | Versioned machine-readable control catalog (ID, severity, scope, rationale, evidence requirements, references, remediation, IAM permissions). |
| `context.py` | `CheckContext` (account, region, clients, thresholds, injectable clock/sleep), `SharedCache` (memoizes results *and failures* so a denied call is made once), `@check` registry, `capture()` which converts any failure into ERROR/NOT_ASSESSED findings. |
| `checks/` | One function per control (or per closely related control group). Pure evidence → verdict logic. |
| `evidence.py` | Pagination, strict typed field access (`require`/`optional`) that raises `ParseError` on malformed responses. |
| `errors.py` | Classification of exceptions into statuses. Never returns PASS. |
| `runner.py` | Expands selected controls × scopes (account or each region), runs units on a thread pool, guarantees each selected control reports a status, sorts results deterministically. |
| `models.py` | `Finding`, `Control`, `Catalog`, `Status`, `Severity`. |
| `reporting/` | Report envelope, JSON/CSV/HTML renderers, filters, owner-only file output. |
| `redaction.py` | Configurable masking of account IDs, access key IDs and IPv4 addresses. |
| `policy.py` | Builds the least-privilege IAM policy from the catalog. |
| `organizations.py` | Optional account listing (separate permissions). |

## Finding model

Every finding carries: stable `finding_id` (hash of control, account, region, resource),
`control_id`, `title`, `account_id`, `region` (`global` for account-scope controls),
`resource_id`, `resource_type`, `severity`, `status`, `message`, `evidence`, `sources` (IAM
actions that produced the evidence), `observed_at` (timezone-aware), `remediation`, and
`uncertainty` (what the check could *not* establish).

## Statuses

| Status | Meaning |
|---|---|
| `PASS` | The evidence collected met the control's criteria. |
| `FAIL` | The evidence shows the criteria are not met. |
| `ERROR` | The check could not run to completion (denied, throttled after retries, malformed response, timeout). **Unknown, not compliant.** |
| `NOT_APPLICABLE` | No in-scope resource exists (e.g. no RDS instances in a region). |
| `NOT_ASSESSED` | The state could not be determined for a non-error reason (region/service unavailable, or the evidence available is insufficient, e.g. bucket ACLs). **Unknown, not compliant.** |

## Error handling, retries, throttling

- Botocore runs in `adaptive` retry mode with a configurable limit on *total* attempts including the first call (default 8; verified against a real local HTTP endpoint, not just stubs) and
  timeouts; throttling that survives the retries is reported as `ERROR` with a message saying so.
- The credential report is polled with exponential backoff (1 s doubling, capped at 15 s, 8 tries).
- Each check isolates failures per resource: one denied bucket does not hide the others.
- A check that raises unexpectedly is converted by the runner into ERROR findings for its
  controls; a check that forgets a selected control yields NOT_ASSESSED. The audit always
  completes with partial results.
- Expired credentials mid-audit (for example an assumed-role session ending) are reported as `ERROR` with an explicit "credentials expired" message.
- Cache entries have per-key locks, so a slow call such as the IAM credential report never blocks unrelated checks.
- Logging never includes credentials or response bodies; error findings keep only the exception
  *type* and the AWS error code context.

## Scope of a control

`account` controls run once (client region = home region; findings use region `global`).
`region` controls run once per audited region. S3 bucket controls run in the region the bucket
lives in (resolved with `BucketRegion` or `GetBucketLocation`); buckets in unaudited regions are
not assessed and COV-001 flags unaudited regions.

## Configured encryption vs effective protection

STO-004, EBS-002 and RDS-002 report the **configured** encryption attribute. They do not verify
that existing S3 objects were written with the configured algorithm, that a KMS key policy or
grants allow the intended principals (and only them), that the key is enabled or rotated, or
that snapshots/replicas inherit encryption. Passing findings carry that caveat in `uncertainty`.
Likewise RDS-001 reports the `PubliclyAccessible` flag, not actual network reachability.
