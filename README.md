# AWS Security Auditing Tool

A **read-only** command-line auditor that evaluates an AWS account against a versioned catalog of
41 documented security controls and produces evidence-backed findings (JSON, CSV, HTML) with
remediation guidance.

- **Never changes your account.** Only `Get*`, `List*`, `Describe*` and
  `GenerateCredentialReport` calls are possible (enforced in code *and* by the sample IAM policy). No auto-remediation.
- **Unknown is not compliant.** An API error, denied permission, throttle or malformed response
  becomes `ERROR`/`NOT_ASSESSED`, never `PASS`.
- **No secrets in arguments or config.** Uses the standard boto3 credential chain (SSO, profiles,
  environment, instance roles) and optional role assumption.
- **Explicit confirmation.** Shows the resolved account ID and regions and requires you to
  confirm the account before auditing.

> **Scope and honesty notes.** Controls are *inspired by* the CIS AWS Foundations Benchmark; this
> project is **not CIS-certified** and does **not** cover the full benchmark. Everything here was
> tested with stubbed AWS responses; **no run against a real AWS account has been performed**
> (see [docs/integration-testing.md](docs/integration-testing.md)).

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash

uv sync
uv run awsauditor --help
```

## Quick start

```bash
# 1. Create a read-only role from policies/audit-full.json (see docs/iam-permissions.md), then sign in:
aws sso login --profile audit-readonly            # or assume the role via --role-arn

# 2. See exactly what would be audited (audits nothing):
uv run awsauditor audit plan --aws-profile audit-readonly --regions us-east-1,eu-west-1

# 3. Run it. You must confirm the resolved account ID:
uv run awsauditor audit run --aws-profile audit-readonly --regions all \
    --audit-profile full --formats json,html --output-dir audit-output \
    --confirm-account 123456789012 --fail-on high
```

Interactive terminals are prompted to type the account ID if `--confirm-account` is omitted;
non-interactive runs (CI) must pass it. A mismatch aborts before any audit API call.

### Commands

| Command | Purpose |
|---|---|
| `controls list [--service s3] [--severity high] [--format json]` | List catalog controls |
| `controls show IAM-001` | Full control definition (rationale, evidence, remediation, references, IAM actions) |
| `config validate audit.toml` | Validate configuration offline; rejects credentials |
| `audit plan` | Resolve account, regions and controls; audit nothing |
| `audit run` | Run the audit and write reports (files `0600`, no overwrite without `--force`) |
| `findings filter report.json --status FAIL,ERROR --min-severity high --control IAM-003 --region us-east-1` | Query a saved report |
| `report diff old.json new.json [--fail-on-regression]` | New failures, resolved findings and results that became unknown between two runs |
| `report export report.json --format html|sarif|csv --output out [--redact --ip-addresses]` | Convert/redact a saved report |
| `keys generate` / `report sign` / `report verify [--public-key K]` | Ed25519 signing and verification of report manifests |
| `policy generate --audit-profile baseline` | Print the least-privilege IAM policy for a profile |
| `org list-accounts` | Optional: list Organization accounts (separate permissions) |

Exit codes: `0` ok · `1` a FAIL at/above `--fail-on` · `2` usage/config/auth error ·
`3` with `--strict`, some results were unknown (ERROR/NOT_ASSESSED).

### Suppressions, SARIF and report integrity

- **Suppressions** (`[[suppressions]]` in the config) record an explicit, expiring acceptance of a
  `FAIL` (control, resource/region globs, reason, owner, mandatory expiry). The finding stays `FAIL`
  and visible with its justification; it only stops counting toward `--fail-on` and the
  `active_failures` total. Expired suppressions are ignored (the finding is active again) and warned
  about, as are entries that match nothing.
- **SARIF 2.1.0** (`--formats sarif`) carries `FAIL` findings and unknown results (`kind: review`)
  with logical (resource) locations and stable fingerprints for security tooling.
- **Manifest:** every `audit run` writes `audit-<stamp>.sha256`; `awsauditor report verify` checks it.
  Alone this detects accidental or naive tampering, not an attacker who can rewrite both files.
- **Signing (Ed25519):** `awsauditor keys generate`, then `audit run --sign` (or `report sign`) and
  `report verify --public-key key.pub`. A valid signature proves the files are exactly what the key
  holder signed; stripping the signature fails verification. See [docs/signing.md](docs/signing.md)
  for what it does and does not prove.
- **Diffing:** `awsauditor report diff old.json new.json --fail-on-regression` for CI gates.

### Configuration

See [examples/config.sample.toml](examples/config.sample.toml). Profiles: built-in `baseline`
(high+critical controls) and `full`; define your own with `services`, `include`, `exclude`,
`min_severity`. Thresholds (unused-credential days, key age, password length, log retention,
sensitive ports) are configurable. External IDs for role assumption are read only from
`AWSAUDITOR_EXTERNAL_ID`.

## Controls (41)

Identity & access (IAM-001..010), logging & monitoring (LOG-001..013), network exposure
(NET-001..006), storage & encryption (STO-001..007, EBS-001..002, RDS-001..002) and region
coverage (COV-001). Full list with severities: [docs/control-mappings.md](docs/control-mappings.md);
machine-readable: [controls/catalog.json](controls/catalog.json).

## Statuses

`PASS` · `FAIL` · `ERROR` (could not run to completion) · `NOT_APPLICABLE` (no in-scope resource) ·
`NOT_ASSESSED` (cannot be determined). Every finding records control ID, resource, region,
severity, status, evidence, the IAM actions that produced it, observation timestamp,
remediation and **uncertainty**. See [docs/architecture.md](docs/architecture.md).

### Sample findings

From the synthetic [examples/sample-report.html](examples/sample-report.html) (fictional
account, stubbed responses, redacted):

| Status | Sev. | Control | Resource | Detail |
|---|---|---|---|---|
| FAIL | critical | IAM-001 | `arn:aws:iam::********3333:root` | Root MFA is not enabled. |
| FAIL | high | NET-001 | `sg-0a1b2c3d4e5f60001` | Sensitive ports are open to the internet (tcp/22 from 0.0.0.0/0). |
| FAIL | high | STO-002 | `arn:aws:s3:::example-open-bucket` | Block Public Access is not fully enabled for this bucket. |
| FAIL | medium | IAM-007 | `account/********3333` | Password policy weaker than baseline: minimum length 8 < 14; reuse prevention 5 < 24. |
| ERROR | medium | LOG-012 | `region/us-east-1` | Permission denied calling DescribeConfigurationRecorders. *(result unknown, not a pass)* |
| PASS | medium | EBS-002 | `vol-0a1b2c3d4e5f60001` | Volume is encrypted. *(uncertainty: configured encryption only; KMS key policy not verified)* |

## IAM permissions

Read-only, `Resource: "*"` (these APIs mostly lack resource-level scoping). Required for every
run: `ec2:DescribeRegions`; everything else is service-specific to the controls you select; a
few actions are optional refinements. Policies in [policies/](policies/) are generated from the
catalog and a test fails if they diverge from the APIs actually called.
Details: [docs/iam-permissions.md](docs/iam-permissions.md).

## Quality and test results

Run on 2026-10-16 in the development environment (Python 3.13.16, boto3 1.43.114):

| Gate | Result |
|---|---|
| `ruff check` / `ruff format --check` | pass / 55 files formatted |
| `mypy --strict` (27 source files) | no issues |
| `pytest tests/unit` | **582 passed**, 0 failed (no AWS credentials; one test talks only to a localhost HTTP server to prove retry behaviour) |
| Coverage | 99.8 % (gate: 95 %) |
| Wheel build + clean-venv install + CLI smoke test | pass (also a CI step) |
| `pip-audit` on the locked dependency set | no known vulnerabilities |
| `detect-secrets` | no secrets detected |
| `tests/integration` | 3 tests, **skipped by default; never run against a real account** |

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml))
runs the same gates on Python 3.11–3.13 with commit-pinned actions and `contents: read`
permissions. The first CI run on `main` passed on all three Python versions.

## Documentation

[Architecture](docs/architecture.md) · [Threat model](docs/threat-model.md) ·
[Control mappings](docs/control-mappings.md) · [IAM permissions](docs/iam-permissions.md) ·
[Report signing](docs/signing.md) · [Integration testing](docs/integration-testing.md) · [Limitations & roadmap](docs/limitations.md) ·
[Implementation plan](docs/implementation-plan.md) · [Contributing](CONTRIBUTING.md) ·
[Security policy](SECURITY.md)

## License

MIT, see [LICENSE](LICENSE).
