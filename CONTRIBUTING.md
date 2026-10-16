# Contributing

## Setup

```bash

uv sync            # installs locked dependencies (Python 3.11+)
```

## Quality gates (all run in CI)

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest tests/unit --cov=awsauditor --cov-fail-under=95
uv export --locked --no-emit-project -o /tmp/req.txt && uv run pip-audit -r /tmp/req.txt --no-deps --disable-pip
git ls-files -z . | xargs -0 uv run detect-secrets-hook --baseline .secrets.baseline
```

## Adding or changing a control

1. Add/modify the entry in `controls/catalog.json` (ID, severity, scope, rationale, evidence
   requirements, remediation, references, **exact IAM actions**). Bump `catalog_version`.
2. Implement the check in `src/awsauditor/checks/` with `@check("ID")`. Rules:
   - Never call anything but read-only APIs (the guard will block it).
   - Every API failure must become `ERROR`/`NOT_ASSESSED` (use `ctx.capture(...)`); never `PASS`.
   - Return `NOT_APPLICABLE` when no in-scope resource exists; always emit a status for each control.
   - Use `evidence.require/optional/paginate`; do not put policy documents, descriptions, tags or
     key identifiers into evidence.
   - State what the check cannot establish in `uncertainty`.
3. Tests: pass, fail, boundary values, no-resource, denied, unsupported region, pagination and
   malformed response where relevant. Use `Harness` (`tests/unit/conftest.py`); unstubbed calls
   fail loudly. Tests must never need AWS credentials.
4. Regenerate policies: `uv run awsauditor policy generate --audit-profile full > policies/audit-full.json`
   (and `baseline`); `test_policy.py` fails if the policy and the APIs used diverge.
5. Update `docs/control-mappings.md` / `docs/iam-permissions.md` tables and `docs/limitations.md`.

## Claims

Do not describe anything as validated against live AWS unless you ran
`docs/integration-testing.md` and recorded the result. Do not claim CIS certification or
complete benchmark coverage.

## Commits and PRs

Small, focused changes with tests. Do not commit reports, credentials or real account data.
