# IAM permissions

The auditor needs **read-only** access. The sample policies in `policies/` are generated from
the control catalog (`awsauditor policy generate`) and a unit test
(`test_zz_policy_covers_exactly_the_actions_the_tests_exercised`) fails if the policy and the
API actions the checks actually call diverge in either direction.

| File | Use |
|---|---|
| `policies/audit-full.json` | Every control in the catalog (profile `full`). |
| `policies/audit-baseline.json` | High and critical controls only (profile `baseline`). |
| `policies/optional-organizations.json` | Optional, separate: `awsauditor org list-accounts`. |

Generate the exact policy for your own profile with:

```bash
awsauditor policy generate --config audit.toml --audit-profile my-profile > my-policy.json
```

## Required, service-specific and optional

| Category | Actions | Notes |
|---|---|---|
| **Required for every run** | `ec2:DescribeRegions` | Region discovery and the COV-001 coverage check. `sts:GetCallerIdentity` is also called but needs no permission. |
| **Service-specific** | The per-service statements (`ReadOnlyIam`, `ReadOnlyS3`, ...) | Needed only if a control that uses that service is selected. Omit a statement and the affected controls report `ERROR` (permission denied), never `PASS`. |
| **Optional** | `s3:GetAccountPublicAccessBlock`, `cloudwatch:DescribeAlarmsForMetric`, `iam:GetPolicyVersion` | Refine results rather than enable a whole control: without the first, bucket checks whose bucket-level Block Public Access is incomplete cannot determine the effective setting and report `ERROR`; without the others, the alarm/policy halves of LOG-008..010 and IAM-006/009 report `ERROR`. |
| **Optional extension (separate policy)** | `organizations:DescribeOrganization`, `organizations:ListAccounts` | Discovery only; the tool never audits accounts automatically. |

Notes on specific actions:

- `iam:GenerateCredentialReport` asks IAM to (re)build the credential report, a prerequisite for
  `iam:GetCredentialReport`. It creates no customer resource. It is the only non-`Get/List/Describe`
  operation the client guard allows, by explicit name.
- Every statement uses `"Resource": "*"` because these list/describe/get APIs mostly do not
  support resource-level scoping. Add conditions such as `aws:RequestedRegion` to constrain
  regions, and attach the policy only to a dedicated audit role.
- The managed policy size limit is 6,144 characters; `audit-full.json` is well under it
  (checked by a test).
- The AWS-managed `SecurityAudit` and `ViewOnlyAccess` policies also work but grant far more
  than is needed.

## Actions by control

| Control | IAM actions used |
|---|---|
| IAM-001 | `iam:GetAccountSummary` |
| IAM-002 | `iam:GetAccountSummary` |
| IAM-003 | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` |
| IAM-004 | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` |
| IAM-005 | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` |
| IAM-006 | `iam:GetPolicyVersion`, `iam:ListPolicies` |
| IAM-007 | `iam:GetAccountPasswordPolicy` |
| IAM-008 | `access-analyzer:ListAnalyzers` |
| IAM-009 | `iam:GetPolicyVersion`, `iam:ListPolicies` |
| LOG-001 | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` |
| LOG-002 | `cloudtrail:DescribeTrails` |
| LOG-003 | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` |
| LOG-004 | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` |
| LOG-005 | `cloudtrail:DescribeTrails`, `s3:GetAccountPublicAccessBlock`, `s3:GetBucketLocation`, `s3:GetBucketPolicyStatus`, `s3:GetBucketPublicAccessBlock` |
| LOG-006 | `cloudtrail:DescribeTrails`, `s3:GetBucketLocation`, `s3:GetBucketLogging` |
| LOG-007 | `logs:DescribeLogGroups` |
| LOG-008 | `cloudtrail:DescribeTrails`, `cloudwatch:DescribeAlarmsForMetric`, `logs:DescribeMetricFilters` |
| LOG-009 | `cloudtrail:DescribeTrails`, `cloudwatch:DescribeAlarmsForMetric`, `logs:DescribeMetricFilters` |
| LOG-010 | `cloudtrail:DescribeTrails`, `cloudwatch:DescribeAlarmsForMetric`, `logs:DescribeMetricFilters` |
| LOG-011 | `guardduty:GetDetector`, `guardduty:ListDetectors` |
| LOG-012 | `config:DescribeConfigurationRecorderStatus`, `config:DescribeConfigurationRecorders`, `config:DescribeDeliveryChannelStatus`, `config:DescribeDeliveryChannels` |
| NET-001 | `ec2:DescribeSecurityGroups` |
| NET-002 | `ec2:DescribeSecurityGroups` |
| NET-003 | `ec2:DescribeSecurityGroups` |
| NET-004 | `ec2:DescribeSecurityGroups` |
| NET-005 | `ec2:DescribeSnapshots` |
| NET-006 | `ec2:DescribeImages` |
| STO-001 | `s3:GetAccountPublicAccessBlock` |
| STO-002 | `s3:GetAccountPublicAccessBlock`, `s3:GetBucketLocation`, `s3:GetBucketPublicAccessBlock`, `s3:ListAllMyBuckets` |
| STO-003 | `s3:GetBucketLocation`, `s3:GetBucketPolicyStatus`, `s3:ListAllMyBuckets` |
| STO-004 | `s3:GetBucketLocation`, `s3:GetEncryptionConfiguration`, `s3:ListAllMyBuckets` |
| STO-005 | `s3:GetBucketLocation`, `s3:GetBucketLogging`, `s3:ListAllMyBuckets` |
| STO-006 | `s3:GetBucketLocation`, `s3:GetBucketPolicy`, `s3:ListAllMyBuckets` |
| EBS-001 | `ec2:GetEbsEncryptionByDefault` |
| EBS-002 | `ec2:DescribeVolumes` |
| RDS-001 | `rds:DescribeDBInstances` |
| RDS-002 | `rds:DescribeDBInstances` |
| COV-001 | `ec2:DescribeRegions` |

## Recommended role setup

1. Create an IAM role in each audited account with the policy above and a trust policy for your
   audit principal. Require MFA or an external ID in the trust policy if the principal is
   shared.
2. Run the tool with `--role-arn`; pass an external ID through the `AWSAUDITOR_EXTERNAL_ID`
   environment variable (never a command-line argument or file).
3. Cross-account CloudTrail log buckets need a bucket policy granting the audit role
   `s3:GetBucketLocation`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicyStatus` and
   `s3:GetBucketLogging`, otherwise LOG-005/LOG-006 report `ERROR`.
