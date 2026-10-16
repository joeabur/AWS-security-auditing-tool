# Sandbox integration tests

These tests call **real AWS APIs** and are **skipped by default**. They have never been run as
part of this repository's CI, and nothing in this project claims live-cloud validation until
someone runs them and records the result (see `docs/integration-testing.md`).

Run only against a dedicated, empty or disposable sandbox account:

```bash
export AWSAUDITOR_INTEGRATION=1
export AWSAUDITOR_INTEGRATION_ACCOUNT=<12-digit sandbox account id>   # safety interlock
export AWS_PROFILE=<read-only sandbox profile>                         # or AWS_ROLE_ARN
uv run pytest tests/integration -m integration -p no:cacheprovider
```

Every test refuses to run unless the resolved account equals
`AWSAUDITOR_INTEGRATION_ACCOUNT`, and the read-only guard in `ClientFactory` rejects any
non-read-only operation, so the tests cannot create, modify or delete resources.
