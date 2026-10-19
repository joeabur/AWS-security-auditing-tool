# Changelog

## Unreleased

- **Ed25519 report signing**: `keys generate`, `audit run --sign`, `report sign`, `report verify --public-key` (supplying a key makes a missing/invalid signature a failure). New dependency: `cryptography`. See `docs/signing.md`.

## 2026.10.1 (catalog)

- New controls: **LOG-013** (all management events recorded), **IAM-010** (AdministratorAccess attached to users/groups), **STO-007** (S3 bucket ACL grants to AllUsers/AuthenticatedUsers).
- LOG-005 now evaluates bucket ACLs, so it no longer ends in `NOT_ASSESSED` when Block Public Access is incomplete.
- `report diff`: compares two saved reports by stable finding ID (new failures, resolved, became unknown, no longer reported).
- `audit run --workers N`.
- **Suppressions**: `[[suppressions]]` in the config (control, resource/region globs, reason, owner, mandatory expiry). Suppressed findings stay `FAIL` and visible; they only stop counting toward `--fail-on` and `active_failures`. Expired and stale entries are warned about.
- **SARIF 2.1.0** output (`--formats sarif`, `report export --format sarif`).
- **Report manifest**: every `audit run` writes `audit-<stamp>.sha256`; `report verify` checks it. Report files are written without newline translation so hashes are stable on every OS.
- Retry limit now counts total attempts (botocore `total_max_attempts`); per-key cache locks; explicit expired/missing-credential errors; wheel smoke test in CI; Dependabot.

## 2026.10.0

- Initial release: 38 controls, JSON/CSV/HTML reports, least-privilege policies, read-only client guard.
