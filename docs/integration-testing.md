# Sandbox integration testing

**Status: not performed.** No test in this repository has been run against a real AWS
account. All results reported by CI and in the README come from unit tests using botocore
`Stubber` responses and injected faults. Treat live-cloud behaviour as unvalidated until you
run the steps below and record the outcome.

## What requires a real account

| Needs a real AWS sandbox | Can be fully covered by unit tests |
|---|---|
| Actual API response shapes and enum values for your regions (`tests/integration`) | Control logic, boundaries, evidence, status mapping |
| Credential report timing and the polling loop under real latency | Polling/backoff logic (injected clock) |
| Opt-in/disabled region behaviour and error codes returned by each service | Classification of known error codes |
| Cross-account CloudTrail bucket behaviour (LOG-005/006) | Same-account logic |
| Throttling behaviour at scale (large accounts) | Retry configuration presence |
| Organization trails, delegated GuardDuty/Config admin accounts | — (not implemented) |

## Procedure

1. Use a **dedicated sandbox account** (preferably empty). Never a production account.
2. Create a role from `policies/audit-full.json`; sign in with SSO or assume the role.
3. Set up deliberately misconfigured fixtures (by hand or IaC, outside this repo):
   a security group open on port 22, an unencrypted EBS volume, a bucket without Block
   Public Access, a weak password policy, GuardDuty disabled. Record expected verdicts.
4. Run the opt-in tests:
   ```bash
   export AWSAUDITOR_INTEGRATION=1 AWSAUDITOR_INTEGRATION_ACCOUNT=<sandbox id> AWS_PROFILE=<profile>
   uv run pytest tests/integration -m integration
   ```
   The tests abort unless the resolved account equals `AWSAUDITOR_INTEGRATION_ACCOUNT`.
5. Run `awsauditor audit run --audit-profile full --regions all` and compare each finding to
   your expected verdicts. Remove permissions one service at a time and confirm affected
   controls become `ERROR` (never `PASS`).
6. Tear down the fixtures.
7. Record the date, tool version, catalog version, regions and results in your own notes. Only
   then describe a check as live-validated.
