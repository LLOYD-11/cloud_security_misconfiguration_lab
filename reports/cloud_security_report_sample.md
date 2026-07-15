# Cloud Security Risk Report

Generated: 2026-06-30

## Executive Summary

This report consolidates 28 finding(s) from offline cloud security analyzers.

## Severity Summary

| Severity | Count |
| --- | ---: |
| Critical | 5 |
| High | 10 |
| Medium | 11 |
| Low | 2 |
| Info | 0 |

## Module Coverage

| Module | Findings |
| --- | ---: |
| cloudtrail | 6 |
| iam | 8 |
| network | 7 |
| storage | 7 |

## Source Files

The source files below are generated analyzer outputs and are not committed to the repository.

- `reports/generated/iam_findings.json`
- `reports/generated/storage_findings.json`
- `reports/generated/network_findings.json`
- `reports/generated/cloudtrail_findings.json`

## Findings

### Critical

#### CLD-001: Root account console login

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `identity/root`
- Evidence: Root ConsoleLogin event from 203.0.113.10 at 2026-06-30T01:00:00Z.
- Impact: Root account use is highly sensitive and may indicate emergency access or account compromise.
- Remediation: Avoid routine root use, confirm the login was authorized, and require MFA on the root account.
- Metadata: actor: arn:aws:iam::111122223333:root, event_id: ConsoleLogin-1, event_name: ConsoleLogin, event_time: 2026-06-30T01:00:00Z, source_ip: 203.0.113.10
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html, https://attack.mitre.org/techniques/T1078/004/

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
- Metadata: exposure_scope: internet-wide, group_name: all-open, rule_index: 1
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

#### CLD-002: MFA device was disabled or deleted

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `identity/alice-admin`
- Evidence: DeactivateMFADevice was called by alice-admin from 198.51.100.20 at 2026-06-30T01:04:00Z.
- Impact: Disabling MFA weakens account protection and may be part of account takeover or persistence activity.
- Remediation: Confirm the MFA change was authorized and re-enable MFA for affected users.
- Metadata: actor: alice-admin, event_id: DeactivateMFADevice-2, event_name: DeactivateMFADevice, event_time: 2026-06-30T01:04:00Z, source_ip: 198.51.100.20
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html, https://attack.mitre.org/techniques/T1098/

#### CLD-004: Bucket access policy changed

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `bucket/public-customer-exports`
- Evidence: PutBucketPolicy was called by alice-admin from 198.51.100.20 at 2026-06-30T01:12:00Z.
- Impact: Bucket policy or public-access changes can expose cloud storage data.
- Remediation: Review the bucket policy diff and restore least-privilege access if the change was not approved.
- Metadata: actor: alice-admin, event_id: PutBucketPolicy-4, event_name: PutBucketPolicy, event_time: 2026-06-30T01:12:00Z, source_ip: 198.51.100.20
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html, https://attack.mitre.org/techniques/T1565/

#### CLD-005: IAM policy configuration changed

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `iam_policy/arn:aws:iam::111122223333:policy/OverBroadAdminPolicy`
- Evidence: CreatePolicyVersion was called by alice-admin from 198.51.100.20 at 2026-06-30T01:15:00Z.
- Impact: IAM policy changes can grant new permissions, create persistence, or weaken least privilege.
- Remediation: Review the IAM policy change and confirm it matches an approved access request.
- Metadata: actor: alice-admin, event_id: CreatePolicyVersion-5, event_name: CreatePolicyVersion, event_time: 2026-06-30T01:15:00Z, source_ip: 198.51.100.20
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html, https://attack.mitre.org/techniques/T1098/

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
- Evidence: Trust policy allows external principal(s): ["arn:aws:iam::999988887777:root"].
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
- Metadata: exposure_scope: internet-wide, group_name: admin-open, port: 22, rule_index: 1, service: SSH
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

#### NET-001: Sensitive RDP port is open to the internet

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-001-admin-open`
- Evidence: Inbound rule 2 allows tcp 3389 from ::/0.
- Impact: RDP exposure can increase the risk of brute force, exploitation, or unauthorized administrative access.
- Remediation: Restrict RDP access to a VPN, bastion host, private CIDR, or specific trusted IP range.
- Metadata: exposure_scope: internet-wide, group_name: admin-open, port: 3389, rule_index: 2, service: RDP
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

#### NET-001: Sensitive MySQL port is open to the internet

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-002-database-public`
- Evidence: Inbound rule 1 allows tcp 3306 from 0.0.0.0/0.
- Impact: MySQL exposure can increase the risk of brute force, exploitation, or unauthorized administrative access.
- Remediation: Restrict MySQL access to a VPN, bastion host, private CIDR, or specific trusted IP range.
- Metadata: exposure_scope: internet-wide, group_name: database-public, port: 3306, rule_index: 1, service: MySQL
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

#### NET-001: Sensitive PostgreSQL port is open to the internet

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-002-database-public`
- Evidence: Inbound rule 2 allows tcp 5432 from 0.0.0.0/0.
- Impact: PostgreSQL exposure can increase the risk of brute force, exploitation, or unauthorized administrative access.
- Remediation: Restrict PostgreSQL access to a VPN, bastion host, private CIDR, or specific trusted IP range.
- Metadata: exposure_scope: internet-wide, group_name: database-public, port: 5432, rule_index: 2, service: PostgreSQL
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

#### CLD-003: Security group configuration changed

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `security_group/sg-001-admin-open`
- Evidence: AuthorizeSecurityGroupIngress was called by alice-admin from 198.51.100.20 at 2026-06-30T01:09:00Z.
- Impact: Security group changes can expose services, enable lateral movement, or weaken network controls.
- Remediation: Review the rule change, verify the business need, and revert unauthorized exposure.
- Metadata: actor: alice-admin, event_id: AuthorizeSecurityGroupIngress-3, event_name: AuthorizeSecurityGroupIngress, event_time: 2026-06-30T01:09:00Z, source_ip: 198.51.100.20
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://attack.mitre.org/techniques/T1578/005/

#### CLD-006: Repeated API failures from one actor and source

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `api_activity/unknown-user@192.0.2.44`
- Evidence: 6 failed API call(s) from unknown-user at 192.0.2.44 within 10 minutes starting 2026-06-30T02:00:00Z.
- Impact: Repeated failed API calls may indicate credential misuse, probing, or brute-force style activity.
- Remediation: Review the source IP, actor, failed API names, and related authentication activity.
- Metadata: actor: unknown-user, error_codes: AccessDenied, UnauthorizedOperation, event_names: AssumeRole, DescribeInstances, GetUser, ListBuckets, ListUsers, failure_count: 6, source_ip: 192.0.2.44, window_minutes: 10
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://attack.mitre.org/techniques/T1110/

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
- Metadata: exposure_scope: internet-wide, group_name: admin-open, rule_index: 1
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

#### NET-003: Security group allows unrestricted outbound traffic

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-003-all-open`
- Evidence: Outbound rule 1 allows -1 all from ::/0.
- Impact: Compromised workloads may communicate freely with internet destinations, making exfiltration or command-and-control traffic harder to contain.
- Remediation: Restrict outbound traffic to required protocols, ports, and destination CIDR ranges where practical.
- Metadata: exposure_scope: internet-wide, group_name: all-open, rule_index: 1
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

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

### Low

#### STO-004: Bucket lacks an explicit encryption configuration

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/analytics-raw-data`
- Evidence: No explicit bucket-level default encryption configuration is present in the input.
- Impact: S3 applies baseline SSE-S3 encryption to new objects, but explicit key-management requirements cannot be confirmed.
- Remediation: For sensitive or regulated data, configure explicit default encryption with an approved KMS key and document key ownership requirements.
- Metadata: None
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html, https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html

#### STO-004: Bucket lacks an explicit encryption configuration

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/public-customer-exports`
- Evidence: No explicit bucket-level default encryption configuration is present in the input.
- Impact: S3 applies baseline SSE-S3 encryption to new objects, but explicit key-management requirements cannot be confirmed.
- Remediation: For sensitive or regulated data, configure explicit default encryption with an approved KMS key and document key ownership requirements.
- Metadata: None
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html, https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html
