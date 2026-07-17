# Cloud Security Risk Report

Generated: 2026-06-30

## Executive Summary

This report consolidates 34 finding(s) from offline cloud security analyzers.

## Severity Summary

| Severity | Count |
| --- | ---: |
| Critical | 6 |
| High | 10 |
| Medium | 16 |
| Low | 2 |
| Info | 0 |

## Module Coverage

| Module | Findings |
| --- | ---: |
| cloudtrail | 6 |
| iam | 9 |
| network | 10 |
| storage | 9 |

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
- Metadata: policy_arn: arn:aws:iam::111122223333:policy/OverBroadAdminPolicy, policy_name: OverBroadAdminPolicy, policy_source: managed, statement_id: FullAdmin
- References: https://attack.mitre.org/techniques/T1078/004/, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### NET-001: Sensitive Docker API without TLS port is allowed on a reported internet-reachable path

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-001-admin-open`
- Evidence: Inbound rule 3 allows tcp 2375 from 0.0.0.0/0. Supplied manual-topology-review context observed at 2026-06-30T04:00:00Z reports the ingress path as reachable for scope 'All attached resources and public ingress rules for TCP 22, 2375, 3389, and 6443 across IPv4 and IPv6': Internet-gateway paths to the attached administration interface were reported reachable for the assessed TCP services.
- Impact: The supplied context reports an active end-to-end path. Unauthorized callers can reach privileged orchestration or host operations through the exposed control-plane endpoint.
- Remediation: Place the endpoint on a private management network, require strong authentication and encryption, and allow only specific administrative sources. Reassess the end-to-end path after remediation.
- Metadata: exposure_scope: internet-wide, group_name: admin-open, port: 2375, protocol: tcp, reachability_direction: ingress, reachability_evidence: Internet-gateway paths to the attached administration interface were reported reachable for the assessed TCP services., reachability_method: manual-topology-review, reachability_observed_at: 2026-06-30T04:00:00Z, reachability_resource_ids: igw-00000000000000001, eni-00000000000000001, reachability_scope: All attached resources and public ingress rules for TCP 22, 2375, 3389, and 6443 across IPv4 and IPv6., reachability_status: reachable, rule_index: 3, service: Docker API without TLS, service_category: control-plane, service_default_severity: critical
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html, https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html, https://docs.docker.com/engine/daemon/remote-access/

#### NET-002: All inbound ports are allowed on a reported internet-reachable path

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-003-all-open`
- Evidence: Inbound rule 1 allows -1 all from 0.0.0.0/0. Supplied manual-topology-review context observed at 2026-06-30T04:10:00Z reports the ingress path as reachable for scope 'All attached resources and public IPv4 ingress rules across every protocol and port': A public ingress path from the internet gateway to an attached network interface was identified.
- Impact: The supplied context reports an active end-to-end path. Any service attached to this security group may be reachable from the public internet.
- Remediation: Remove all-port public inbound access and allow only required ports from trusted CIDR ranges. Reassess the end-to-end path after remediation.
- Metadata: exposure_scope: internet-wide, group_name: all-open, reachability_direction: ingress, reachability_evidence: A public ingress path from the internet gateway to an attached network interface was identified., reachability_method: manual-topology-review, reachability_observed_at: 2026-06-30T04:10:00Z, reachability_resource_ids: igw-00000000000000001, eni-00000000000000003, reachability_scope: All attached resources and public IPv4 ingress rules across every protocol and port., reachability_status: reachable, rule_index: 1
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html, https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html, https://attack.mitre.org/techniques/T1578/005/

#### STO-002: Bucket ACL grants public access

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/public-customer-exports`
- Evidence: ACL grant 1 gives READ permission to AllUsers. Object Ownership is ObjectWriter.
- Impact: Objects or bucket metadata may be exposed to public or broadly authenticated users.
- Remediation: Remove public ACL grants and rely on private bucket ownership plus scoped IAM policies.
- Metadata: grantee: AllUsers, object_ownership: ObjectWriter, permission: READ
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html, https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html, https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html

#### STO-003: Bucket policy allows an effectively public principal

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/public-customer-exports`
- Evidence: Allow statement uses Principal "*" with action "s3:GetObject" and resource "arn:aws:s3:::public-customer-exports/*". Condition {"IpAddress": {"aws:SourceIp": "0.0.0.0/1"}} does not establish an AWS-recognized fixed-value guardrail.
- Impact: Bucket data may be publicly accessible because the statement is public under S3 Block Public Access policy-evaluation rules.
- Remediation: Replace the broad principal with specific AWS principals or add a supported fixed-value condition, then validate the result with IAM Access Analyzer for S3.
- Metadata: block_public_policy: false, condition_keys: aws:SourceIp, principal_element: Principal, restrict_public_buckets: false, statement_index: 1, statement_sid: PublicRead
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
- Metadata: boundary_document: available, permissions_boundary: arn:aws:iam::111122223333:policy/DataEngineeringBoundary, policy_name: BroadS3WritePolicy, policy_source: inline, statement_id: BroadS3
- References: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### IAM-008: Cross-account role trust

- Module: `iam`
- Category: `identity-and-access`
- Resource: `role/third-party-audit-role`
- Evidence: Trust policy allows external principal(s): ["arn:aws:iam::999988887777:root"]. Recognized guardrails: none.
- Impact: An external account or principal may be able to assume this role.
- Remediation: Restrict the trusted principal, require an external ID for third-party access or an organization condition for internal multi-account access, and confirm the business need.
- Metadata: policy_name: trust-policy, statement_id: ExternalAccountTrust, trust_guardrails: none
- References: https://attack.mitre.org/techniques/T1199/, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html

#### NET-001: Sensitive SSH port is allowed on a reported internet-reachable path

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-001-admin-open`
- Evidence: Inbound rule 1 allows tcp 22 from 0.0.0.0/0. Supplied manual-topology-review context observed at 2026-06-30T04:00:00Z reports the ingress path as reachable for scope 'All attached resources and public ingress rules for TCP 22, 2375, 3389, and 6443 across IPv4 and IPv6': Internet-gateway paths to the attached administration interface were reported reachable for the assessed TCP services.
- Impact: The supplied context reports an active end-to-end path. The exposed remote-administration endpoint increases the risk of credential attacks and unauthorized host access.
- Remediation: Restrict administration to a VPN, bastion host, private management network, or specific trusted source addresses. Reassess the end-to-end path after remediation.
- Metadata: exposure_scope: internet-wide, group_name: admin-open, port: 22, protocol: tcp, reachability_direction: ingress, reachability_evidence: Internet-gateway paths to the attached administration interface were reported reachable for the assessed TCP services., reachability_method: manual-topology-review, reachability_observed_at: 2026-06-30T04:00:00Z, reachability_resource_ids: igw-00000000000000001, eni-00000000000000001, reachability_scope: All attached resources and public ingress rules for TCP 22, 2375, 3389, and 6443 across IPv4 and IPv6., reachability_status: reachable, rule_index: 1, service: SSH, service_category: remote-administration, service_default_severity: high
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html, https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html, https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html

#### NET-001: Sensitive RDP port is allowed on a reported internet-reachable path

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-001-admin-open`
- Evidence: Inbound rule 2 allows tcp 3389 from ::/0. Supplied manual-topology-review context observed at 2026-06-30T04:00:00Z reports the ingress path as reachable for scope 'All attached resources and public ingress rules for TCP 22, 2375, 3389, and 6443 across IPv4 and IPv6': Internet-gateway paths to the attached administration interface were reported reachable for the assessed TCP services.
- Impact: The supplied context reports an active end-to-end path. The exposed remote-administration endpoint increases the risk of credential attacks and unauthorized host access.
- Remediation: Restrict administration to a VPN, bastion host, private management network, or specific trusted source addresses. Reassess the end-to-end path after remediation.
- Metadata: exposure_scope: internet-wide, group_name: admin-open, port: 3389, protocol: tcp, reachability_direction: ingress, reachability_evidence: Internet-gateway paths to the attached administration interface were reported reachable for the assessed TCP services., reachability_method: manual-topology-review, reachability_observed_at: 2026-06-30T04:00:00Z, reachability_resource_ids: igw-00000000000000001, eni-00000000000000001, reachability_scope: All attached resources and public ingress rules for TCP 22, 2375, 3389, and 6443 across IPv4 and IPv6., reachability_status: reachable, rule_index: 2, service: RDP, service_category: remote-administration, service_default_severity: high
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html, https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html, https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html

#### NET-001: Sensitive Kubernetes API server port is allowed on a reported internet-reachable path

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-001-admin-open`
- Evidence: Inbound rule 4 allows tcp 6443 from 0.0.0.0/0. Supplied manual-topology-review context observed at 2026-06-30T04:00:00Z reports the ingress path as reachable for scope 'All attached resources and public ingress rules for TCP 22, 2375, 3389, and 6443 across IPv4 and IPv6': Internet-gateway paths to the attached administration interface were reported reachable for the assessed TCP services.
- Impact: The supplied context reports an active end-to-end path. Unauthorized callers can reach privileged orchestration or host operations through the exposed control-plane endpoint.
- Remediation: Place the endpoint on a private management network, require strong authentication and encryption, and allow only specific administrative sources. Reassess the end-to-end path after remediation.
- Metadata: exposure_scope: internet-wide, group_name: admin-open, port: 6443, protocol: tcp, reachability_direction: ingress, reachability_evidence: Internet-gateway paths to the attached administration interface were reported reachable for the assessed TCP services., reachability_method: manual-topology-review, reachability_observed_at: 2026-06-30T04:00:00Z, reachability_resource_ids: igw-00000000000000001, eni-00000000000000001, reachability_scope: All attached resources and public ingress rules for TCP 22, 2375, 3389, and 6443 across IPv4 and IPv6., reachability_status: reachable, rule_index: 4, service: Kubernetes API server, service_category: control-plane, service_default_severity: high
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html, https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html, https://kubernetes.io/docs/reference/networking/ports-and-protocols/

#### NET-001: Sensitive Redis port permits public sources without a reported reachable path

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-002-database-public`
- Evidence: Inbound rule 3 allows tcp 6379 from 0.0.0.0/0. Supplied aws-reachability-analyzer context observed at 2026-06-30T04:05:00Z reports the ingress path as not reachable for scope 'All attached resources and public IPv4 ingress rules for TCP 3306, 5432, and 6379': Separate IPv4 path analyses for all listed database ports found no route from the internet gateway to an attached interface.
- Impact: The supplied context reports no current end-to-end path, reducing immediate exposure. The permissive rule remains a latent risk if attachments, addresses, routes, or intermediary controls change.
- Remediation: Keep the service on private subnets, require authentication and encryption, and allow only the application security groups or trusted source ranges that need access. Reassess the end-to-end path after remediation.
- Metadata: exposure_scope: internet-wide, group_name: database-public, port: 6379, protocol: tcp, reachability_direction: ingress, reachability_evidence: Separate IPv4 path analyses for all listed database ports found no route from the internet gateway to an attached interface., reachability_method: aws-reachability-analyzer, reachability_observed_at: 2026-06-30T04:05:00Z, reachability_resource_ids: eni-00000000000000002, rtb-00000000000000002, reachability_scope: All attached resources and public IPv4 ingress rules for TCP 3306, 5432, and 6379., reachability_status: not_reachable, rule_index: 3, service: Redis, service_category: data-service, service_default_severity: critical
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html, https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html, https://redis.io/docs/latest/operate/oss_and_stack/management/security/

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

#### IAM-002: Wildcard action allowed

- Module: `iam`
- Category: `identity-and-access`
- Resource: `role/third-party-audit-role`
- Evidence: Allow statement uses wildcard action pattern(s): ['iam:Get*', 'iam:List*'].
- Impact: The policy can automatically include multiple current or future API operations that match the wildcard.
- Remediation: Replace wildcard action patterns with the minimum explicit API actions required by the workload.
- Metadata: policy_name: AuditReadOnly, policy_source: inline, statement_id: AuditRead
- References: https://attack.mitre.org/techniques/T1078/004/, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### IAM-003: Wildcard resource scope

- Module: `iam`
- Category: `identity-and-access`
- Resource: `role/third-party-audit-role`
- Evidence: Allow statement uses Resource "*".
- Impact: The permission is not limited to specific cloud resources.
- Remediation: Scope the statement to specific ARNs wherever the service supports resource-level permissions.
- Metadata: policy_name: AuditReadOnly, policy_source: inline, statement_id: AuditRead
- References: https://attack.mitre.org/techniques/T1078/004/, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### IAM-003: Wildcard resource scope

- Module: `iam`
- Category: `identity-and-access`
- Resource: `user/alice-admin`
- Evidence: Allow statement uses Resource "*".
- Impact: The permission is not limited to specific cloud resources.
- Remediation: Scope the statement to specific ARNs wherever the service supports resource-level permissions.
- Metadata: policy_arn: arn:aws:iam::111122223333:policy/OverBroadAdminPolicy, policy_name: OverBroadAdminPolicy, policy_source: managed, statement_id: FullAdmin
- References: https://attack.mitre.org/techniques/T1078/004/, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### IAM-005: Sensitive action without MFA condition

- Module: `iam`
- Category: `identity-and-access`
- Resource: `user/alice-admin`
- Evidence: Sensitive action is allowed without an MFA condition.
- Impact: Compromised credentials could be used for privileged activity without an additional identity check.
- Remediation: Add an MFA condition for sensitive IAM, STS, KMS, account, or organization actions where appropriate.
- Metadata: policy_arn: arn:aws:iam::111122223333:policy/OverBroadAdminPolicy, policy_name: OverBroadAdminPolicy, policy_source: managed, statement_id: FullAdmin
- References: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

#### IAM-006: User MFA is disabled

- Module: `iam`
- Category: `identity-and-access`
- Resource: `user/alice-admin`
- Evidence: User has an active console password without MFA.
- Impact: A compromised console password has less resistance without MFA.
- Remediation: Enable MFA for interactive IAM users or remove console access.
- Metadata: policy_name: credential-report, statement_id: mfa
- References: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html

#### IAM-007: Long-lived access key

- Module: `iam`
- Category: `identity-and-access`
- Resource: `user/alice-admin`
- Evidence: Active access key age is 142 days.
- Impact: Long-lived access keys increase the window of exposure if credentials are leaked.
- Remediation: Rotate old access keys and prefer temporary role credentials where possible.
- Metadata: policy_name: credential-report, statement_id: AKIAEXAMPLEALICE
- References: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html

#### NET-001: Sensitive MySQL/Aurora port permits public sources without a reported reachable path

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-002-database-public`
- Evidence: Inbound rule 1 allows tcp 3306 from 0.0.0.0/0. Supplied aws-reachability-analyzer context observed at 2026-06-30T04:05:00Z reports the ingress path as not reachable for scope 'All attached resources and public IPv4 ingress rules for TCP 3306, 5432, and 6379': Separate IPv4 path analyses for all listed database ports found no route from the internet gateway to an attached interface.
- Impact: The supplied context reports no current end-to-end path, reducing immediate exposure. The permissive rule remains a latent risk if attachments, addresses, routes, or intermediary controls change.
- Remediation: Keep the database on private subnets and allow only the application security groups or trusted source ranges that require access. Reassess the end-to-end path after remediation.
- Metadata: exposure_scope: internet-wide, group_name: database-public, port: 3306, protocol: tcp, reachability_direction: ingress, reachability_evidence: Separate IPv4 path analyses for all listed database ports found no route from the internet gateway to an attached interface., reachability_method: aws-reachability-analyzer, reachability_observed_at: 2026-06-30T04:05:00Z, reachability_resource_ids: eni-00000000000000002, rtb-00000000000000002, reachability_scope: All attached resources and public IPv4 ingress rules for TCP 3306, 5432, and 6379., reachability_status: not_reachable, rule_index: 1, service: MySQL/Aurora, service_category: database, service_default_severity: high
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html, https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html, https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html

#### NET-001: Sensitive PostgreSQL port permits public sources without a reported reachable path

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-002-database-public`
- Evidence: Inbound rule 2 allows tcp 5432 from 0.0.0.0/0. Supplied aws-reachability-analyzer context observed at 2026-06-30T04:05:00Z reports the ingress path as not reachable for scope 'All attached resources and public IPv4 ingress rules for TCP 3306, 5432, and 6379': Separate IPv4 path analyses for all listed database ports found no route from the internet gateway to an attached interface.
- Impact: The supplied context reports no current end-to-end path, reducing immediate exposure. The permissive rule remains a latent risk if attachments, addresses, routes, or intermediary controls change.
- Remediation: Keep the database on private subnets and allow only the application security groups or trusted source ranges that require access. Reassess the end-to-end path after remediation.
- Metadata: exposure_scope: internet-wide, group_name: database-public, port: 5432, protocol: tcp, reachability_direction: ingress, reachability_evidence: Separate IPv4 path analyses for all listed database ports found no route from the internet gateway to an attached interface., reachability_method: aws-reachability-analyzer, reachability_observed_at: 2026-06-30T04:05:00Z, reachability_resource_ids: eni-00000000000000002, rtb-00000000000000002, reachability_scope: All attached resources and public IPv4 ingress rules for TCP 3306, 5432, and 6379., reachability_status: not_reachable, rule_index: 2, service: PostgreSQL, service_category: database, service_default_severity: high
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html, https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html, https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html

#### NET-003: Unrestricted outbound traffic is allowed on a reported internet path

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-001-admin-open`
- Evidence: Outbound rule 1 allows -1 all from 0.0.0.0/0. Supplied manual-topology-review context observed at 2026-06-30T04:00:00Z reports the egress path as reachable for scope 'All attached resources and public IPv4 egress rules': The attached administration interface had a default route through the internet gateway.
- Impact: The supplied context reports an active end-to-end path. Compromised workloads may communicate freely with internet destinations, making exfiltration or command-and-control traffic harder to contain.
- Remediation: Restrict outbound traffic to required protocols, ports, and destination CIDR ranges where practical. Reassess the end-to-end path after remediation.
- Metadata: exposure_scope: internet-wide, group_name: admin-open, reachability_direction: egress, reachability_evidence: The attached administration interface had a default route through the internet gateway., reachability_method: manual-topology-review, reachability_observed_at: 2026-06-30T04:00:00Z, reachability_resource_ids: eni-00000000000000001, igw-00000000000000001, reachability_scope: All attached resources and public IPv4 egress rules., reachability_status: reachable, rule_index: 1
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html, https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html

#### NET-003: Unrestricted outbound traffic is allowed on a reported internet path

- Module: `network`
- Category: `network-exposure`
- Resource: `security_group/sg-003-all-open`
- Evidence: Outbound rule 1 allows -1 all from ::/0. Supplied manual-topology-review context observed at 2026-06-30T04:10:00Z reports the egress path as reachable for scope 'All attached resources and public IPv6 egress rules across every protocol and port': A public egress path from the attached network interface to the internet gateway was identified.
- Impact: The supplied context reports an active end-to-end path. Compromised workloads may communicate freely with internet destinations, making exfiltration or command-and-control traffic harder to contain.
- Remediation: Restrict outbound traffic to required protocols, ports, and destination CIDR ranges where practical. Reassess the end-to-end path after remediation.
- Metadata: exposure_scope: internet-wide, group_name: all-open, reachability_direction: egress, reachability_evidence: A public egress path from the attached network interface to the internet gateway was identified., reachability_method: manual-topology-review, reachability_observed_at: 2026-06-30T04:10:00Z, reachability_resource_ids: eni-00000000000000003, igw-00000000000000001, reachability_scope: All attached resources and public IPv6 egress rules across every protocol and port., reachability_status: reachable, rule_index: 1
- References: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html, https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html, https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html

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

#### STO-006: Bucket access control lists remain enabled

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/analytics-raw-data`
- Evidence: S3 Object Ownership is BucketOwnerPreferred, so bucket and object ACLs can still affect access.
- Impact: ACL-based permissions and cross-account object ownership can make access harder to reason about and can preserve unintended grants.
- Remediation: Migrate required ACL permissions to policies, reset the bucket ACL to private, and use BucketOwnerEnforced unless an ACL-dependent workload is documented.
- Metadata: object_ownership: BucketOwnerPreferred
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html, https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-acl-prohibited.html

#### STO-006: Bucket access control lists remain enabled

- Module: `storage`
- Category: `data-exposure`
- Resource: `bucket/public-customer-exports`
- Evidence: S3 Object Ownership is ObjectWriter, so bucket and object ACLs can still affect access.
- Impact: ACL-based permissions and cross-account object ownership can make access harder to reason about and can preserve unintended grants.
- Remediation: Migrate required ACL permissions to policies, reset the bucket ACL to private, and use BucketOwnerEnforced unless an ACL-dependent workload is documented.
- Metadata: object_ownership: ObjectWriter
- References: https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html, https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-acl-prohibited.html

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
