# Limitations, unsupported checks and roadmap

## Unsupported or partial (by design for this version)

- **Not a complete benchmark.** 41 controls; many CIS AWS Foundations recommendations and most
  service-specific controls are not implemented (see `control-mappings.md`).
- **IAM policies:** only attached *customer-managed* policies are analysed (IAM-006/009), plus
  attachments of the AWS-managed `AdministratorAccess` policy to users/groups (IAM-010; roles are
  counted, not flagged). Inline policies, other AWS-managed policies, permission boundaries,
  SCPs, resource policies and effective-permission simulation are not evaluated. Statements with a
  `Condition` are not flagged.
- **Root MFA:** presence only; hardware vs virtual is not distinguished.
- **CloudTrail:** multi-region/logging/validation/delivery/CloudWatch integration and "all
  management events" (LOG-013) are checked; data event selectors, KMS encryption, and organization trails owned by other
  accounts are not.
- **Metric filters (LOG-008..010):** matched by heuristic token matching on the filter pattern;
  alarm notification targets (SNS subscriptions) are not verified. Only unauthorized API calls,
  root usage and console sign-in without MFA are covered.
- **Security groups:** only exact `0.0.0.0/0` and `::/0` count as public; prefix lists, broad
  CIDRs (e.g. `/1`), attachment to resources, NACLs and route tables are not evaluated.
- **S3:** bucket ACLs are evaluated (STO-007, and LOG-005); object ACLs, access points, Object
  Ownership settings and object-level encryption are not. Buckets in unaudited regions are skipped (COV-001 flags the gap).
- **Encryption controls** verify configuration only (see `architecture.md`).
- **RDS:** DB instances only (clusters, snapshots, Aurora-specific attributes not queried);
  public accessibility is a flag, not proven reachability.
- **Cross-account CloudTrail buckets** report `ERROR` unless the bucket owner grants read access.
- **Organizations:** account listing only; no automatic multi-account audit. Audit each account
  with its own role.
- **Partitions:** GovCloud/China are supported by design (partition from the caller ARN) but
  untested.
- **Credential lifetime:** an assumed-role session lasts up to `role_duration_seconds` (default
  1 h); very long audits are not automatically refreshed. Calls after expiry are reported as
  `ERROR` ("credentials expired"), never as passes.
- **No live-cloud validation** has been performed (see `integration-testing.md`).

## Operational limitations

- Read-only calls are subject to account API rate limits; large accounts (thousands of security
  groups/buckets) can take minutes and retry under throttling.
- Reports are point-in-time. Signing is optional (Ed25519); `signed_at` is self-asserted, with no trusted timestamp, and key distribution is out of band (see `signing.md`).
- `AccountMFAEnabled`, credential report and similar data can lag changes by minutes to hours.
- Windows is untested.

## Prioritized roadmap

1. **Run and record the sandbox integration pass** (highest value: converts unit-test
   confidence into live evidence).
2. Inline-policy analysis; IAM Access Analyzer findings.
3. CloudTrail data events and KMS; VPC flow logs; KMS key rotation; S3 data events.
4. S3 access points and Object Ownership evaluation.
5. RDS clusters and snapshots; EBS snapshot encryption; Lambda/ECR/EKS public exposure.
6. Multi-account runner using Organizations discovery plus per-account role assumption.
7. OCSF output. (SARIF shipped.) (Diff mode using the stable `finding_id` shipped: `report diff`.)
8. Optional encrypted-at-rest report output; trusted timestamping and HSM/KMS-backed signing. (Ed25519 signing shipped.)
