# Implementation plan (as executed)

1. **Inspect** the repository (a portfolio site; no existing AWS tooling) and verify dependency
   compatibility (`uv lock`; boto3/botocore 1.43.x, pydantic 2.14, typer 0.27, pytest 9.1, ruff 0.17,
   mypy 2.4, pip-audit 2.10, detect-secrets 1.5 on Python 3.11–3.13).
2. **Catalog first:** define the 38 controls, severities, evidence, remediation and IAM actions.
3. **Foundations:** models, config (credentials unrepresentable), session + read-only guard,
   region discovery, error classification.
4. **Framework:** check context/registry, evidence helpers, runner with partial results.
5. **Checks** in stages: IAM → logging/monitoring → network → storage → EBS/RDS → coverage.
6. **Outputs:** report model, JSON/CSV/HTML, redaction, protected files, policy generation.
7. **CLI:** controls, config, audit plan/run, findings filter, report export, policy, org.
8. **Tests** per control, a fault matrix over every check, runner/CLI/report tests, a test that
   ties the published IAM policy to the APIs actually called.
9. **Quality gates:** ruff, mypy `--strict`, coverage, pip-audit, detect-secrets, CI with pinned actions.
10. **Docs and examples.**
