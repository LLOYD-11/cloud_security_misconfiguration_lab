# Cloud Security Risk Report

Generated: 2026-06-30

## Executive Summary

This report consolidates 23 finding(s) from offline cloud security analyzers.

## Severity Summary

| Severity | Count |
| --- | ---: |
| Critical | 4 |
| High | 7 |
| Medium | 12 |
| Low | 0 |
| Info | 0 |

## Module Coverage

| Module | Findings |
| --- | ---: |
| iam | 9 |
| network | 7 |
| storage | 7 |

## Source Files

- `reports/generated/iam_findings.json`
- `reports/generated/storage_findings.json`
- `reports/generated/network_findings.json`

## Findings

### Critical

#### IAM-001: Administrator-style wildcard permission

- Module: `iam`
- Category: `identity-and-access`
- Resource: `user/alice-admin`
- Evidence: Allow statement grants Action "*" on Resource "*".
- Impact: The principal may have full administrative access across the account.
- Remediation: Replace wildcard administrator access with task-specific actions and scoped resources.
- Metadata: policy_name: OverBroadAdminPolicy, statement_id: FullAdmin
- References: https://attack.mitre.org/techniques/T1078/004/, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### NET-002: Security group allows all inbound ports from the internet

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-003-all-open`
- Evidence: Inbound rule 1 allows -1 all from 0.0.0.0/0.
- Impact: Any exposed service attached to this security group may be reachable from the public internet.
- Remediation: Remove all-port public inbound access and allow only required ports from trusted CIDR ranges.
- Metadata: group_name: all-open, rule_index: 1
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html, https://attack.mitre.org/techniques/T1578/005/

#### STO-002: Bucket ACL grants public access

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/public-customer-exports`
- Evidence: ACL grant 1 gives READ permission to AllUsers.
- Impact: Objects or bucket metadata may be exposed to public or broadly authenticated users.
- Remediation: Remove public ACL grants and rely on private bucket ownership plus scoped IAM policies.
- Metadata: grantee: AllUsers, permission: READ
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html, https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html

#### STO-003: Bucket policy allows public principal

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/public-customer-exports`
- Evidence: Allow statement grants access to public principal: "*".
- Impact: Bucket data may be publicly accessible depending on the allowed action and resource scope.
- Remediation: Replace public principals with specific AWS principals and validate whether anonymous access is required.
- Metadata: statement_index: 1
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html, https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html

### High

#### IAM-004: Broad S3 write permission

- Module: `iam`
- Category: `identity-and-access`
- Resource: `user/data-engineer`
- Evidence: S3 write action with broad resource scope: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'] on ['arn:aws:s3:::company-data-*/*'].
- Impact: The principal may alter or delete data across a broad set of storage resources.
- Remediation: Restrict S3 write actions to the exact bucket and prefix required for the workload.
- Metadata: policy_name: BroadS3WritePolicy, statement_id: BroadS3
- References: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### IAM-008: Cross-account role trust

- Module: `iam`
- Category: `identity-and-access`
- Resource: `role/third-party-audit-role`
- Evidence: Trust policy allows an external principal: {"AWS": "arn:aws:iam::999988887777:root"}.
- Impact: An external account or principal may be able to assume this role.
- Remediation: Require an external ID, restrict the trusted principal, and confirm the business need for cross-account access.
- Metadata: policy_name: trust-policy, statement_id: ExternalAccountTrust
- References: https://attack.mitre.org/techniques/T1199/, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### NET-001: Sensitive SSH port is open to the internet

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-001-admin-open`
- Evidence: Inbound rule 1 allows tcp 22 from 0.0.0.0/0.
- Impact: SSH exposure can increase the risk of brute force, exploitation, or unauthorized administrative access.
- Remediation: Restrict SSH access to a VPN, bastion host, private CIDR, or specific trusted IP range.
- Metadata: group_name: admin-open, port: 22, rule_index: 1, service: SSH
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

#### NET-001: Sensitive RDP port is open to the internet

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-001-admin-open`
- Evidence: Inbound rule 2 allows tcp 3389 from ::/0.
- Impact: RDP exposure can increase the risk of brute force, exploitation, or unauthorized administrative access.
- Remediation: Restrict RDP access to a VPN, bastion host, private CIDR, or specific trusted IP range.
- Metadata: group_name: admin-open, port: 3389, rule_index: 2, service: RDP
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

#### NET-001: Sensitive MySQL port is open to the internet

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-002-database-public`
- Evidence: Inbound rule 1 allows tcp 3306 from 0.0.0.0/0.
- Impact: MySQL exposure can increase the risk of brute force, exploitation, or unauthorized administrative access.
- Remediation: Restrict MySQL access to a VPN, bastion host, private CIDR, or specific trusted IP range.
- Metadata: group_name: database-public, port: 3306, rule_index: 1, service: MySQL
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

#### NET-001: Sensitive PostgreSQL port is open to the internet

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-002-database-public`
- Evidence: Inbound rule 2 allows tcp 5432 from 0.0.0.0/0.
- Impact: PostgreSQL exposure can increase the risk of brute force, exploitation, or unauthorized administrative access.
- Remediation: Restrict PostgreSQL access to a VPN, bastion host, private CIDR, or specific trusted IP range.
- Metadata: group_name: database-public, port: 5432, rule_index: 2, service: PostgreSQL
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

#### STO-001: S3 public access block is incomplete

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/public-customer-exports`
- Evidence: Disabled or missing public access block controls: ['block_public_acls', 'ignore_public_acls', 'block_public_policy', 'restrict_public_buckets'].
- Impact: The bucket has weaker guardrails against public ACLs or public bucket policies.
- Remediation: Enable all four S3 Block Public Access settings unless a documented exception is required.
- Metadata: disabled_controls: block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html, https://attack.mitre.org/techniques/T1619/

### Medium

#### IAM-003: Wildcard resource scope

- Module: `iam`
- Category: `identity-and-access`
- Resource: `role/third-party-audit-role`
- Evidence: Allow statement uses Resource "*".
- Impact: The permission is not limited to specific cloud resources.
- Remediation: Scope the statement to specific ARNs wherever the service supports resource-level permissions.
- Metadata: policy_name: AuditReadOnly, statement_id: AuditRead
- References: https://attack.mitre.org/techniques/T1078/004/, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### IAM-003: Wildcard resource scope

- Module: `iam`
- Category: `identity-and-access`
- Resource: `user/alice-admin`
- Evidence: Allow statement uses Resource "*".
- Impact: The permission is not limited to specific cloud resources.
- Remediation: Scope the statement to specific ARNs wherever the service supports resource-level permissions.
- Metadata: policy_name: OverBroadAdminPolicy, statement_id: FullAdmin
- References: https://attack.mitre.org/techniques/T1078/004/, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### IAM-005: Sensitive action without MFA condition

- Module: `iam`
- Category: `identity-and-access`
- Resource: `role/third-party-audit-role`
- Evidence: Sensitive action is allowed without an MFA condition.
- Impact: Compromised credentials could be used for privileged activity without an additional identity check.
- Remediation: Add an MFA condition for sensitive IAM, STS, KMS, account, or organization actions where appropriate.
- Metadata: policy_name: AuditReadOnly, statement_id: AuditRead
- References: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### IAM-005: Sensitive action without MFA condition

- Module: `iam`
- Category: `identity-and-access`
- Resource: `user/alice-admin`
- Evidence: Sensitive action is allowed without an MFA condition.
- Impact: Compromised credentials could be used for privileged activity without an additional identity check.
- Remediation: Add an MFA condition for sensitive IAM, STS, KMS, account, or organization actions where appropriate.
- Metadata: policy_name: OverBroadAdminPolicy, statement_id: FullAdmin
- References: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### IAM-006: User MFA is disabled

- Module: `iam`
- Category: `identity-and-access`
- Resource: `user/alice-admin`
- Evidence: User metadata shows MFA is not enabled.
- Impact: A password or access-key compromise has less resistance without multi-factor authentication.
- Remediation: Enable MFA for interactive users and prefer short-lived role credentials for automation.
- Metadata: policy_name: user-metadata, statement_id: mfa
- References: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### IAM-007: Long-lived access key

- Module: `iam`
- Category: `identity-and-access`
- Resource: `user/alice-admin`
- Evidence: Access key age is 142 days.
- Impact: Long-lived access keys increase the window of exposure if credentials are leaked.
- Remediation: Rotate old access keys and prefer temporary credentials where possible.
- Metadata: policy_name: access-key-metadata, statement_id: AKIAEXAMPLEALICE
- References: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### NET-003: Security group allows unrestricted outbound traffic

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-001-admin-open`
- Evidence: Outbound rule 1 allows -1 all from 0.0.0.0/0.
- Impact: Compromised workloads may communicate freely with internet destinations, making exfiltration or command-and-control traffic harder to contain.
- Remediation: Restrict outbound traffic to required protocols, ports, and destination CIDR ranges where practical.
- Metadata: group_name: admin-open, rule_index: 1
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

#### NET-003: Security group allows unrestricted outbound traffic

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-003-all-open`
- Evidence: Outbound rule 1 allows -1 all from ::/0.
- Impact: Compromised workloads may communicate freely with internet destinations, making exfiltration or command-and-control traffic harder to contain.
- Remediation: Restrict outbound traffic to required protocols, ports, and destination CIDR ranges where practical.
- Metadata: group_name: all-open, rule_index: 1
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

#### STO-004: Bucket encryption is disabled

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/analytics-raw-data`
- Evidence: Bucket encryption configuration is missing or disabled.
- Impact: Stored data may lack a default server-side encryption control.
- Remediation: Enable default server-side encryption, preferably with a managed KMS key for sensitive data.
- Metadata: None
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html

#### STO-004: Bucket encryption is disabled

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/public-customer-exports`
- Evidence: Bucket encryption configuration is missing or disabled.
- Impact: Stored data may lack a default server-side encryption control.
- Remediation: Enable default server-side encryption, preferably with a managed KMS key for sensitive data.
- Metadata: None
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html

#### STO-005: Bucket versioning is not enabled

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/analytics-raw-data`
- Evidence: Bucket versioning status is Disabled.
- Impact: Accidental deletion, overwrite, or destructive activity may be harder to recover from.
- Remediation: Enable bucket versioning for important data and pair it with lifecycle rules if storage cost matters.
- Metadata: versioning_status: Disabled
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html

#### STO-005: Bucket versioning is not enabled

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/public-customer-exports`
- Evidence: Bucket versioning status is Suspended.
- Impact: Accidental deletion, overwrite, or destructive activity may be harder to recover from.
- Remediation: Enable bucket versioning for important data and pair it with lifecycle rules if storage cost matters.
- Metadata: versioning_status: Suspended
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
