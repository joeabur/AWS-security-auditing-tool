# Control mappings

Catalog version: `2026.10.1` (`controls/catalog.json`, schema version 1).

## What "CIS-inspired" means here

The controls are **inspired by** themes in the CIS AWS Foundations Benchmark and by AWS
security best practices. This project:

- is **not** CIS-certified and makes **no** claim of conformance or complete coverage;
- deliberately does **not** cite CIS recommendation numbers, because numbering and wording
  change between benchmark versions and the benchmark text is licensed by CIS. Map each
  control to the section numbers of the benchmark version you use, from the licensed document
  (<https://www.cisecurity.org/benchmark/amazon_web_services>);
- implements thresholds (unused-credential days, key age, password length) as **configurable**
  values with defaults chosen to be common practice, not as authoritative requirements.

## Controls

| ID | Severity | Scope | Title | Benchmark theme (CIS-inspired, not a section citation) |
|---|---|---|---|---|
| COV-001 | low | account | All enabled regions in the account were audited | Coverage |
| EBS-001 | medium | region | EBS encryption by default is enabled in the region | Storage: encryption at rest |
| EBS-002 | medium | region | EBS volumes are encrypted | Storage: encryption at rest |
| IAM-001 | critical | account | Root account has MFA enabled | Identity and Access Management: root account protection |
| IAM-002 | critical | account | Root account has no active access keys | Identity and Access Management: root account protection |
| IAM-003 | high | account | IAM users with console access have MFA | Identity and Access Management: multi-factor authentication |
| IAM-004 | medium | account | Credentials unused beyond the configured threshold are disabled | Identity and Access Management: credential hygiene |
| IAM-005 | medium | account | Active access keys are rotated within the configured age | Identity and Access Management: credential hygiene |
| IAM-006 | high | account | No attached customer-managed policy grants full administrative access | Identity and Access Management: least privilege |
| IAM-007 | medium | account | IAM password policy meets the configured baseline | Identity and Access Management: password policy |
| IAM-008 | low | region | IAM Access Analyzer is active in the region | Identity and Access Management: external access analysis |
| IAM-009 | medium | account | No attached customer-managed policy uses broad service wildcards or Allow with NotAction | Identity and Access Management: least privilege |
| IAM-010 | high | account | AdministratorAccess is not attached to IAM users or groups | Identity and Access Management: least privilege |
| LOG-001 | high | account | A multi-region CloudTrail trail is logging | Logging and monitoring: CloudTrail |
| LOG-002 | medium | region | CloudTrail log file validation is enabled | Logging and monitoring: CloudTrail |
| LOG-003 | medium | region | CloudTrail is logging and delivering to S3 without errors | Logging and monitoring: CloudTrail |
| LOG-004 | low | region | CloudTrail delivers events to CloudWatch Logs | Logging and monitoring: CloudTrail |
| LOG-005 | high | region | CloudTrail S3 bucket is not publicly accessible | Logging and monitoring: CloudTrail log bucket protection |
| LOG-006 | low | region | CloudTrail S3 bucket has server access logging enabled | Logging and monitoring: CloudTrail log bucket protection |
| LOG-007 | low | region | CloudWatch log groups retain logs for at least the configured period | Logging and monitoring: log retention |
| LOG-008 | low | region | Unauthorized API call metric filter and alarm exist | Logging and monitoring: CloudTrail metric filters and alarms |
| LOG-009 | medium | region | Root account usage metric filter and alarm exist | Logging and monitoring: CloudTrail metric filters and alarms |
| LOG-010 | medium | region | Console sign-in without MFA metric filter and alarm exist | Logging and monitoring: CloudTrail metric filters and alarms |
| LOG-011 | medium | region | GuardDuty detector is enabled in the region | Logging and monitoring: threat detection |
| LOG-012 | medium | region | AWS Config recorder is recording and delivering in the region | Logging and monitoring: configuration recording |
| NET-001 | high | region | Security groups do not allow public ingress to sensitive ports | Networking: security group exposure |
| NET-002 | medium | region | Default security groups restrict all traffic | Networking: security group exposure |
| NET-003 | high | region | Security groups do not allow public ingress on all ports or protocols | Networking: security group exposure |
| NET-004 | low | region | Security groups do not allow unrestricted egress on all protocols | Networking: security group exposure |
| NET-005 | high | region | No EBS snapshots owned by the account are public | Networking: public resource exposure |
| NET-006 | high | region | No AMIs owned by the account are public | Networking: public resource exposure |
| RDS-001 | high | region | RDS DB instances are not publicly accessible | Storage: database exposure |
| RDS-002 | medium | region | RDS DB instances have storage encryption enabled | Storage: encryption at rest |
| STO-001 | medium | account | S3 account-level Block Public Access is fully enabled | Storage: S3 public access |
| STO-002 | high | region | S3 bucket Block Public Access is effectively enabled | Storage: S3 public access |
| STO-003 | high | region | S3 bucket policy does not make the bucket public | Storage: S3 public access |
| STO-004 | medium | region | S3 bucket has default encryption configured | Storage: encryption at rest |
| STO-005 | low | region | S3 bucket has server access logging enabled | Storage: S3 logging |
| STO-006 | medium | region | S3 bucket policy denies non-TLS requests | Storage: encryption in transit |
| STO-007 | high | region | S3 bucket ACL does not grant access to everyone | Storage: S3 public access |

## Benchmark themes not covered

Not implemented (see `docs/limitations.md`): management-event selector verification, KMS key
rotation, VPC flow logs, network ACL rules, route-table peering review, S3 object-level
(data-event) logging, Security Hub/Inspector, support-role checks, IAM inline-policy analysis and AWS-managed
policies other than AdministratorAccess, SAML/OIDC provider review, and many service-specific controls.
