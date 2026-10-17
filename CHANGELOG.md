# Changelog

## 2026.10.1 (catalog) / unreleased

- New controls: **IAM-010** (AdministratorAccess attached to users/groups), **STO-007** (S3 bucket ACL grants to AllUsers/AuthenticatedUsers).
- LOG-005 now evaluates bucket ACLs, so it no longer ends in `NOT_ASSESSED` when Block Public Access is incomplete.
- `report diff`: compares two saved reports by stable finding ID (new failures, resolved, became unknown, no longer reported).
- `audit run --workers N`.
- Retry limit now counts total attempts (botocore `total_max_attempts`); per-key cache locks; explicit expired/missing-credential errors; wheel smoke test in CI; Dependabot.

## 2026.10.0

- Initial release: 38 controls, JSON/CSV/HTML reports, least-privilege policies, read-only client guard.
