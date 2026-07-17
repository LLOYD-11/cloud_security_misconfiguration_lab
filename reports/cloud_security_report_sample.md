# Cloud Security Risk Report

Generated: 2026-06-30

## Executive Summary

This report consolidates 39 findings from offline cloud security analyzers.

## Severity Summary

| Severity | Count |
| --- | ---: |
| Critical | 8 |
| High | 13 |
| Medium | 16 |
| Low | 2 |
| Info | 0 |

## Analysis Coverage

Resource counts use `evaluated/discovered`. A partial result means one or more evidence gaps affected analysis coverage.

| Module | Input | Coverage | Evaluated Resources | Skipped Evidence | Warnings | Findings |
| --- | --- | --- | --- | ---: | ---: | ---: |
| cloudtrail | simplified (1 file(s)) | complete | event: 17/17 | 0 | 0 | 11 |
| iam | simplified (1 file(s)) | complete | group: 1/1; role: 1/1; root-account: 1/1; user: 3/3 | 0 | 0 | 9 |
| network | simplified (1 file(s)) | complete | security-group: 4/4 | 0 | 0 | 10 |
| storage | simplified (1 file(s)) | complete | bucket: 3/3 | 0 | 0 | 9 |

## Prioritized Remediation Plan

Priorities use the transparent rules below rather than an opaque numeric risk score. Incident response and configuration hardening remain separate work types.

| Priority | Meaning |
| --- | --- |
| P0 | Immediate response for critical incidents, or high-severity incidents with high correlation confidence. |
| P1 | Urgent investigation or hardening for other incidents, critical findings, and configuration linked to a P0 incident. |
| P2 | Near-term hardening for high findings and configuration linked to another incident. |
| P3 | Planned hardening for medium, low, and informational findings. |

| Priority | Work Item | Type | Severity / Confidence | Priority Basis | Required Action |
| --- | --- | --- | --- | --- | --- |
| **P0** | `REM-5D8F441B5D84` Respond: Monitoring defenses weakened during persistence activity | Incident response | Critical / High | Critical-severity correlated incident `CTI-B36042008211` has high confidence across 8 rules and 8 events. | Validate the actor, session context, source IP, and change authorization.<br>Restore affected logging or detection controls and verify telemetry continuity.<br>Contain the identity, remove unapproved credentials or trust, and restore MFA.<br>Cancel unauthorized key deletion or re-enable the key, then assess dependent data.<br>Preserve relevant CloudTrail records and open an incident-response case. |
| **P1** | `REM-79AD2D996911` Respond: Repeated failed API activity | Incident response | Medium / Medium | Medium-severity correlated incident `CTI-E0E40ECCC4EB` has medium confidence across 1 rule and 6 events. | Validate the actor, session context, source IP, and change authorization.<br>Review failed API names, error codes, source reputation, and related authentication.<br>Preserve relevant CloudTrail records and open an incident-response case. |
| **P1** | `REM-A4689FB86F28` Remediate: Root account console login | Configuration | Critical / High | 1 critical finding for `CLD-001` affects 1 resource. | Avoid routine root use, confirm the login was authorized, and require MFA on the root account. |
| **P1** | `REM-C567677196FF` Remediate: Audit or threat-detection control was disabled | Configuration | Critical / High | 1 critical finding for `CLD-010` affects 1 resource. Related incident context: `CTI-B36042008211`. | Confirm authorization, restore the control, verify telemetry continuity, and investigate surrounding activity. |
| **P1** | `REM-CA21BB5BCF9F` Remediate: KMS key was scheduled for deletion | Configuration | Critical / High | 1 critical finding for `CLD-011` affects 1 resource. Related incident context: `CTI-B36042008211`. | Validate the change, cancel unauthorized deletion or re-enable the key, and identify dependent resources. |
| **P1** | `REM-8A5F5F4AE73D` Remediate: Administrator-style wildcard permission | Configuration | Critical / High | 1 critical finding for `IAM-001` affects 1 resource. | Replace wildcard administrator access with task-specific actions and scoped resources. |
| **P1** | `REM-472AF2848FDE` Remediate: Bucket ACL grants public access | Configuration | Critical / High | 1 critical finding for `STO-002` affects 1 resource. | Remove public ACL grants and rely on private bucket ownership plus scoped IAM policies. |
| **P1** | `REM-48730C11A926` Remediate: Sensitive Docker API without TLS port is allowed on a reported internet-reachable path | Configuration | Critical / Medium | 1 critical finding for `NET-001` affects 1 resource. | Place the endpoint on a private management network, require strong authentication and encryption, and allow only specific administrative sources. Reassess the end-to-end path after remediation. |
| **P1** | `REM-960E2AD72458` Remediate: All inbound ports are allowed on a reported internet-reachable path | Configuration | Critical / Medium | 1 critical finding for `NET-002` affects 1 resource. | Remove all-port public inbound access and allow only required ports from trusted CIDR ranges. Reassess the end-to-end path after remediation. |
| **P1** | `REM-5694CBAFF416` Remediate: Bucket policy allows an effectively public principal | Configuration | Critical / Medium | 1 critical finding for `STO-003` affects 1 resource. | Replace the broad principal with specific AWS principals or add a supported fixed-value condition, then validate the result with IAM Access Analyzer for S3. |
| **P1** | `REM-218BA736A752` Remediate: Bucket access policy changed | Configuration | High / High | 1 high finding for `CLD-004` affects 1 resource. Related incident context: `CTI-B36042008211`. | Review the bucket policy diff and restore least-privilege access if the change was not approved. |
| **P1** | `REM-6840CF733DE1` Remediate: Persistent cloud credential was created | Configuration | High / High | 1 high finding for `CLD-008` affects 1 resource. Related incident context: `CTI-B36042008211`. | Confirm the credential was approved, identify where it was stored, and remove or rotate it if unauthorized. |
| **P1** | `REM-7B9BBE55101F` Remediate: IAM policy configuration changed | Configuration | High / High | 1 high finding for `CLD-005` affects 1 resource. Related incident context: `CTI-B36042008211`. | Review the IAM policy change and confirm it matches an approved access request. |
| **P1** | `REM-835078868E32` Remediate: MFA device was disabled or deleted | Configuration | High / High | 1 high finding for `CLD-002` affects 1 resource. Related incident context: `CTI-B36042008211`. | Confirm the MFA change was authorized and re-enable MFA for affected users. |
| **P1** | `REM-9852ED596B1C` Remediate: Role trust policy was changed | Configuration | High / High | 1 high finding for `CLD-009` affects 1 resource. Related incident context: `CTI-B36042008211`. | Review the trust-policy diff, validate every principal and condition, and remove unapproved trust. |
| **P1** | `REM-73FD85C1C735` Remediate: Security group configuration changed | Configuration | Medium / High | 1 medium finding for `CLD-003` affects 1 resource. Related incident context: `CTI-B36042008211`. | Review the rule change, verify the business need, and revert unauthorized exposure. |
| **P2** | `REM-7F2097F63694` Remediate: IAM user console login did not use MFA | Configuration | High / High | 1 high finding for `CLD-007` affects 1 resource. | Validate the login, require MFA for the user, and investigate the source and subsequent activity. |
| **P2** | `REM-AA2E0DB9C7AA` Remediate: S3 public access block is incomplete | Configuration | High / High | 1 high finding for `STO-001` affects 1 resource. | Enable all four S3 Block Public Access settings unless a documented exception is required. |
| **P2** | `REM-3D102F59A686` Remediate: Cross-account role trust | Configuration | High / Medium | 1 high finding for `IAM-008` affects 1 resource. | Restrict the trusted principal, require an external ID for third-party access or an organization condition for internal multi-account access, and confirm the business need. |
| **P2** | `REM-F6D2FD8E72D2` Remediate: Broad S3 write permission | Configuration | High / Medium | 1 high finding for `IAM-004` affects 1 resource. | Restrict S3 write actions to the exact bucket and prefix required for the workload. |
| **P2** | `REM-92197FD9421A` Remediate: Sensitive RDP port is allowed on a reported internet-reachable path | Configuration | High / Medium | 1 high finding for `NET-001` affects 1 resource. | Restrict administration to a VPN, bastion host, private management network, or specific trusted source addresses. Reassess the end-to-end path after remediation. |
| **P2** | `REM-9336DCB72283` Remediate: Sensitive SSH port is allowed on a reported internet-reachable path | Configuration | High / Medium | 1 high finding for `NET-001` affects 1 resource. | Restrict administration to a VPN, bastion host, private management network, or specific trusted source addresses. Reassess the end-to-end path after remediation. |
| **P2** | `REM-D7539AB21A5A` Remediate: Sensitive Redis port permits public sources without a reported reachable path | Configuration | High / Medium | 1 high finding for `NET-001` affects 1 resource. | Keep the service on private subnets, require authentication and encryption, and allow only the application security groups or trusted source ranges that need access. Reassess the end-to-end path after remediation. |
| **P2** | `REM-F08519785932` Remediate: Sensitive Kubernetes API server port is allowed on a reported internet-reachable path | Configuration | High / Medium | 1 high finding for `NET-001` affects 1 resource. | Place the endpoint on a private management network, require strong authentication and encryption, and allow only specific administrative sources. Reassess the end-to-end path after remediation. |
| **P2** | `REM-A4C2BE15A9A4` Remediate: Repeated API failures from one actor and source | Configuration | Medium / Medium | 1 medium finding for `CLD-006` affects 1 resource. Related incident context: `CTI-E0E40ECCC4EB`. | Review the source IP, actor, failed API names, and related authentication activity. |
| **P3** | `REM-6406D5571955` Remediate: Long-lived access key | Configuration | Medium / High | 1 medium finding for `IAM-007` affects 1 resource. | Rotate old access keys and prefer temporary role credentials where possible. |
| **P3** | `REM-AD7EB22B927C` Remediate: Wildcard action allowed | Configuration | Medium / High | 1 medium finding for `IAM-002` affects 1 resource. | Replace wildcard action patterns with the minimum explicit API actions required by the workload. |
| **P3** | `REM-C84B6739BF5D` Remediate: User MFA is disabled | Configuration | Medium / High | 1 medium finding for `IAM-006` affects 1 resource. | Enable MFA for interactive IAM users or remove console access. |
| **P3** | `REM-EFE0374480FB` Remediate: Wildcard resource scope | Configuration | Medium / High | 2 medium findings for `IAM-003` affect 2 resources. | Scope the statement to specific ARNs wherever the service supports resource-level permissions. |
| **P3** | `REM-8F6FEF3C158F` Remediate: Bucket versioning is not enabled | Configuration | Medium / High | 2 medium findings for `STO-005` affect 2 resources. | Enable bucket versioning for important data and pair it with lifecycle rules if storage cost matters. |
| **P3** | `REM-AA92CBE5F64A` Remediate: Bucket access control lists remain enabled | Configuration | Medium / High | 2 medium findings for `STO-006` affect 2 resources. | Migrate required ACL permissions to policies, reset the bucket ACL to private, and use BucketOwnerEnforced unless an ACL-dependent workload is documented. |
| **P3** | `REM-D7708838BDDF` Remediate: Sensitive action without MFA condition | Configuration | Medium / Medium | 1 medium finding for `IAM-005` affects 1 resource. | Add an MFA condition for sensitive IAM, STS, KMS, account, or organization actions where appropriate. |
| **P3** | `REM-2C60AE22CF65` Remediate: Unrestricted outbound traffic is allowed on a reported internet path | Configuration | Medium / Medium | 2 medium findings for `NET-003` affect 2 resources. | Restrict outbound traffic to required protocols, ports, and destination CIDR ranges where practical. Reassess the end-to-end path after remediation. |
| **P3** | `REM-CCE0D4DF2E4E` Remediate: Sensitive MySQL/Aurora port permits public sources without a reported reachable path | Configuration | Medium / Medium | 1 medium finding for `NET-001` affects 1 resource. | Keep the database on private subnets and allow only the application security groups or trusted source ranges that require access. Reassess the end-to-end path after remediation. |
| **P3** | `REM-F6284BAA9FF6` Remediate: Sensitive PostgreSQL port permits public sources without a reported reachable path | Configuration | Medium / Medium | 1 medium finding for `NET-001` affects 1 resource. | Keep the database on private subnets and allow only the application security groups or trusted source ranges that require access. Reassess the end-to-end path after remediation. |
| **P3** | `REM-AA4A9249F3A9` Remediate: Bucket lacks an explicit encryption configuration | Configuration | Low / High | 2 low findings for `STO-004` affect 2 resources. | For sensitive or regulated data, configure explicit default encryption with an approved KMS key and document key ownership requirements. |

## Triggered Rule Context

Confidence describes how directly the available evidence supports the rule condition. It does not establish malicious intent.

`direct` mappings substantially match the detector condition; `related` mappings provide useful context without claiming equivalent coverage.

| Rule | Catalog Title | Confidence | Finding Severities | Findings | Control Mappings |
| --- | --- | --- | --- | ---: | --- |
| `CLD-001` | Root account console login | High | critical | 1 | MITRE ATT&CK Enterprise T1078.004 (related) |
| `CLD-002` | MFA device was disabled or deleted | High | high | 1 | MITRE ATT&CK Enterprise T1098 (direct) |
| `CLD-003` | Security group configuration changed | High | medium | 1 | MITRE ATT&CK Enterprise T1578.005 (direct) |
| `CLD-004` | Bucket access policy changed | High | high | 1 | MITRE ATT&CK Enterprise T1565 (related) |
| `CLD-005` | IAM policy configuration changed | High | high | 1 | MITRE ATT&CK Enterprise T1098 (direct) |
| `CLD-006` | Repeated API failures from one actor and source | Medium | medium | 1 | MITRE ATT&CK Enterprise T1110 (related) |
| `CLD-007` | IAM user console login did not use MFA | High | high | 1 | MITRE ATT&CK Enterprise T1078.004 (related) |
| `CLD-008` | Persistent cloud credential was created | High | high | 1 | MITRE ATT&CK Enterprise T1098.001 (direct) |
| `CLD-009` | Role trust policy was changed | High | high | 1 | MITRE ATT&CK Enterprise T1098.003 (direct) |
| `CLD-010` | Audit or threat-detection control was disabled | High | critical | 1 | MITRE ATT&CK Enterprise T1685 (direct)<br>MITRE ATT&CK Enterprise T1685.002 (related) |
| `CLD-011` | KMS key was disabled or scheduled for deletion | High | critical | 1 | MITRE ATT&CK Enterprise T1485 (related) |
| `IAM-001` | Administrator-style wildcard permission | High | critical | 1 | AWS Security Hub CSPM IAM.1 (direct) |
| `IAM-002` | Wildcard action allowed | High | medium | 1 | AWS Security Hub CSPM IAM.21 (related) |
| `IAM-003` | Wildcard resource scope | High | medium | 2 | AWS Security Hub CSPM IAM.1 (related) |
| `IAM-004` | Broad S3 write permission | Medium | high | 1 | MITRE ATT&CK Enterprise T1485 (related) |
| `IAM-005` | Sensitive action without MFA condition | Medium | medium | 1 | AWS Security Hub CSPM IAM.5 (related) |
| `IAM-006` | User MFA is disabled | High | medium | 1 | AWS Security Hub CSPM IAM.5 (direct)<br>CIS AWS Foundations Benchmark 1.9 (direct) |
| `IAM-007` | Long-lived access key | High | medium | 1 | AWS Security Hub CSPM IAM.3 (direct)<br>CIS AWS Foundations Benchmark 1.13 (direct) |
| `IAM-008` | Broad or external role trust | Medium | high | 1 | MITRE ATT&CK Enterprise T1199 (related) |
| `NET-001` | Sensitive service port permits public traffic | Medium | critical, high, medium | 7 | AWS Security Hub CSPM EC2.18 (related)<br>AWS Security Hub CSPM EC2.19 (related)<br>AWS Security Hub CSPM EC2.53 (related)<br>AWS Security Hub CSPM EC2.54 (related)<br>CIS AWS Foundations Benchmark 5.3 (related)<br>CIS AWS Foundations Benchmark 5.4 (related) |
| `NET-002` | All inbound ports permit public traffic | Medium | critical | 1 | AWS Security Hub CSPM EC2.18 (direct)<br>AWS Security Hub CSPM EC2.19 (direct) |
| `NET-003` | Security group permits unrestricted outbound traffic | Medium | medium | 2 | MITRE ATT&CK Enterprise T1041 (related) |
| `STO-001` | S3 public access block is incomplete | High | high | 1 | AWS Security Hub CSPM S3.1 (related)<br>AWS Security Hub CSPM S3.8 (direct)<br>CIS AWS Foundations Benchmark 2.1.4 (direct) |
| `STO-002` | Bucket ACL grants public access | High | critical | 1 | AWS Security Hub CSPM S3.2 (related)<br>AWS Security Hub CSPM S3.3 (related)<br>CIS AWS Foundations Benchmark 2.1.4 (related) |
| `STO-003` | Bucket policy allows an effectively public principal | Medium | critical | 1 | AWS Security Hub CSPM S3.2 (related)<br>AWS Security Hub CSPM S3.3 (related)<br>AWS Security Hub CSPM S3.8 (direct)<br>CIS AWS Foundations Benchmark 2.1.4 (direct) |
| `STO-004` | Bucket lacks an explicit encryption configuration | High | low | 2 | AWS Security Hub CSPM S3.17 (related) |
| `STO-005` | Bucket versioning is not enabled | High | medium | 2 | AWS Security Hub CSPM S3.14 (direct) |
| `STO-006` | Bucket access control lists remain enabled | High | medium | 2 | AWS Security Hub CSPM S3.12 (direct) |

## Source Files

The source files below are generated analyzer outputs and are not committed to the repository.

- `reports/generated/iam_findings.json`
- `reports/generated/storage_findings.json`
- `reports/generated/network_findings.json`
- `reports/generated/cloudtrail_findings.json`
- `reports/generated/cloudtrail_incidents.json`
- `reports/generated/iam_analysis_summary.json`
- `reports/generated/storage_analysis_summary.json`
- `reports/generated/network_analysis_summary.json`
- `reports/generated/cloudtrail_analysis_summary.json`

## Correlated Incidents

These incidents group related CloudTrail signals by actor, source IP, and a bounded time window. They support triage and do not prove malicious intent.

| Incident | Severity | Confidence | Actor | Window | Findings / Events |
| --- | --- | --- | --- | --- | --- |
| `CTI-B36042008211` | Critical | High | `alice-admin` | 2026-06-30T01:04:00Z to 2026-06-30T01:23:00Z | 8 / 8 |
| `CTI-E0E40ECCC4EB` | Medium | Medium | `unknown-user` | 2026-06-30T02:00:00Z to 2026-06-30T02:08:00Z | 1 / 6 |

### CTI-B36042008211: Monitoring defenses weakened during persistence activity

- Actor and source: `alice-admin` from `198.51.100.20`
- Window: 2026-06-30T01:04:00Z to 2026-06-30T01:23:00Z
- Severity and confidence: Critical / High
- Correlated rules: CLD-002, CLD-003, CLD-004, CLD-005, CLD-008, CLD-009, CLD-010, CLD-011
- Events and findings: 8 events, 8 findings
- Resources: bucket/public-customer-exports, iam_policy/arn:aws:iam::111122223333:policy/OverBroadAdminPolicy, identity/alice-admin, identity/backup-operator, kms_key/1234abcd-12ab-34cd-56ef-1234567890ab, role/production-admin, security_control/12abc34d567e8fa901bc2d34eexample, security_group/sg-001-admin-open
- Summary: alice-admin generated 8 suspicious signals across 8 rules from 198.51.100.20 between 2026-06-30T01:04:00Z and 2026-06-30T01:23:00Z: CLD-002, CLD-003, CLD-004, CLD-005, CLD-008, CLD-009, CLD-010, CLD-011.
- Recommended actions: Validate the actor, session context, source IP, and change authorization. Restore affected logging or detection controls and verify telemetry continuity. Contain the identity, remove unapproved credentials or trust, and restore MFA. Cancel unauthorized key deletion or re-enable the key, then assess dependent data. Preserve relevant CloudTrail records and open an incident-response case.
- References: https://attack.mitre.org/techniques/T1098/, https://attack.mitre.org/techniques/T1098/001/, https://attack.mitre.org/techniques/T1098/003/, https://attack.mitre.org/techniques/T1485/, https://attack.mitre.org/techniques/T1565/, https://attack.mitre.org/techniques/T1578/005/, https://attack.mitre.org/techniques/T1685/, https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html, https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html, https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html, https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html, https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html

### CTI-E0E40ECCC4EB: Repeated failed API activity

- Actor and source: `unknown-user` from `192.0.2.44`
- Window: 2026-06-30T02:00:00Z to 2026-06-30T02:08:00Z
- Severity and confidence: Medium / Medium
- Correlated rules: CLD-006
- Events and findings: 6 events, 1 finding
- Resources: api_activity/unknown-user@192.0.2.44
- Summary: unknown-user generated 1 suspicious signal across 1 rule from 192.0.2.44 between 2026-06-30T02:00:00Z and 2026-06-30T02:08:00Z: CLD-006.
- Recommended actions: Validate the actor, session context, source IP, and change authorization. Review failed API names, error codes, source reputation, and related authentication. Preserve relevant CloudTrail records and open an incident-response case.
- References: https://attack.mitre.org/techniques/T1110/, https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html

## Findings

### Critical

#### CLD-001: Root account console login

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `identity/root`
- Evidence: Root ConsoleLogin event from 203.0.113.10 at 2026-06-30T01:00:00Z.
- Impact: Root account use is highly sensitive and may indicate emergency access or account compromise.
- Remediation: Avoid routine root use, confirm the login was authorized, and require MFA on the root account.
- Metadata: actor: arn:aws:iam::111122223333:root, aws_region: us-east-1, event_id: 00000000-0000-4000-8000-000000000001, event_name: ConsoleLogin, event_source: signin.amazonaws.com, event_time: 2026-06-30T01:00:00Z, identity_type: Root, source_ip: 203.0.113.10, user_agent: Mozilla/5.0 (sample)
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html, https://attack.mitre.org/techniques/T1078/004/

#### CLD-010: Audit or threat-detection control was disabled

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `security_control/12abc34d567e8fa901bc2d34eexample`
- Evidence: DeleteDetector was called by alice-admin from 198.51.100.20 at 2026-06-30T01:21:00Z.
- Impact: Disabling logging or detection reduces visibility and can conceal later malicious activity.
- Remediation: Confirm authorization, restore the control, verify telemetry continuity, and investigate surrounding activity.
- Metadata: actor: alice-admin, aws_region: ap-southeast-2, event_id: 00000000-0000-4000-8000-000000000015, event_name: DeleteDetector, event_source: guardduty.amazonaws.com, event_time: 2026-06-30T01:21:00Z, identity_type: IAMUser, source_ip: 198.51.100.20, user_agent: aws-cli/2.x
- References: https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html, https://attack.mitre.org/techniques/T1685/

#### CLD-011: KMS key was scheduled for deletion

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `kms_key/1234abcd-12ab-34cd-56ef-1234567890ab`
- Evidence: ScheduleKeyDeletion was called by alice-admin from 198.51.100.20 at 2026-06-30T01:23:00Z.
- Impact: Deleting the key can permanently make dependent encrypted data unrecoverable.
- Remediation: Validate the change, cancel unauthorized deletion or re-enable the key, and identify dependent resources.
- Metadata: actor: alice-admin, aws_region: ap-southeast-2, event_id: 00000000-0000-4000-8000-000000000016, event_name: ScheduleKeyDeletion, event_source: kms.amazonaws.com, event_time: 2026-06-30T01:23:00Z, identity_type: IAMUser, source_ip: 198.51.100.20, user_agent: aws-cli/2.x
- References: https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html, https://attack.mitre.org/techniques/T1485/

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
- Metadata: actor: alice-admin, aws_region: us-east-1, event_id: 00000000-0000-4000-8000-000000000002, event_name: DeactivateMFADevice, event_source: iam.amazonaws.com, event_time: 2026-06-30T01:04:00Z, identity_type: IAMUser, source_ip: 198.51.100.20, user_agent: aws-cli/2.x
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html, https://attack.mitre.org/techniques/T1098/

#### CLD-004: Bucket access policy changed

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `bucket/public-customer-exports`
- Evidence: PutBucketPolicy was called by alice-admin from 198.51.100.20 at 2026-06-30T01:12:00Z.
- Impact: Bucket policy or public-access changes can expose cloud storage data.
- Remediation: Review the bucket policy diff and restore least-privilege access if the change was not approved.
- Metadata: actor: alice-admin, aws_region: ap-southeast-2, event_id: 00000000-0000-4000-8000-000000000004, event_name: PutBucketPolicy, event_source: s3.amazonaws.com, event_time: 2026-06-30T01:12:00Z, identity_type: IAMUser, source_ip: 198.51.100.20, user_agent: aws-cli/2.x
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html, https://attack.mitre.org/techniques/T1565/

#### CLD-005: IAM policy configuration changed

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `iam_policy/arn:aws:iam::111122223333:policy/OverBroadAdminPolicy`
- Evidence: CreatePolicyVersion was called by alice-admin from 198.51.100.20 at 2026-06-30T01:15:00Z.
- Impact: IAM policy changes can grant new permissions, create persistence, or weaken least privilege.
- Remediation: Review the IAM policy change and confirm it matches an approved access request.
- Metadata: actor: alice-admin, aws_region: us-east-1, event_id: 00000000-0000-4000-8000-000000000005, event_name: CreatePolicyVersion, event_source: iam.amazonaws.com, event_time: 2026-06-30T01:15:00Z, identity_type: IAMUser, source_ip: 198.51.100.20, user_agent: aws-cli/2.x
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html, https://attack.mitre.org/techniques/T1098/

#### CLD-007: IAM user console login did not use MFA

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `identity/legacy-operator`
- Evidence: legacy-operator completed ConsoleLogin without MFA from 203.0.113.55 at 2026-06-30T01:30:00Z.
- Impact: A password-only console session has less resistance to stolen credentials and account takeover.
- Remediation: Validate the login, require MFA for the user, and investigate the source and subsequent activity.
- Metadata: actor: legacy-operator, aws_region: us-east-1, event_id: 00000000-0000-4000-8000-000000000017, event_name: ConsoleLogin, event_source: signin.amazonaws.com, event_time: 2026-06-30T01:30:00Z, identity_type: IAMUser, source_ip: 203.0.113.55, user_agent: Mozilla/5.0 (sample)
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html, https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html, https://attack.mitre.org/techniques/T1078/004/

#### CLD-008: Persistent cloud credential was created

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `identity/backup-operator`
- Evidence: CreateAccessKey was called by alice-admin from 198.51.100.20 at 2026-06-30T01:17:00Z.
- Impact: A new key, password, certificate, or service credential can provide persistent access outside the original session.
- Remediation: Confirm the credential was approved, identify where it was stored, and remove or rotate it if unauthorized.
- Metadata: actor: alice-admin, aws_region: us-east-1, event_id: 00000000-0000-4000-8000-000000000013, event_name: CreateAccessKey, event_source: iam.amazonaws.com, event_time: 2026-06-30T01:17:00Z, identity_type: IAMUser, source_ip: 198.51.100.20, user_agent: aws-cli/2.x
- References: https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html, https://attack.mitre.org/techniques/T1098/001/

#### CLD-009: Role trust policy was changed

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `role/production-admin`
- Evidence: UpdateAssumeRolePolicy was called by alice-admin from 198.51.100.20 at 2026-06-30T01:19:00Z.
- Impact: A changed trust policy can let a new principal assume the role and retain or escalate access.
- Remediation: Review the trust-policy diff, validate every principal and condition, and remove unapproved trust.
- Metadata: actor: alice-admin, aws_region: us-east-1, event_id: 00000000-0000-4000-8000-000000000014, event_name: UpdateAssumeRolePolicy, event_source: iam.amazonaws.com, event_time: 2026-06-30T01:19:00Z, identity_type: IAMUser, source_ip: 198.51.100.20, user_agent: aws-cli/2.x
- References: https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html, https://attack.mitre.org/techniques/T1098/003/

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
- Metadata: actor: alice-admin, aws_region: ap-southeast-2, event_id: 00000000-0000-4000-8000-000000000003, event_name: AuthorizeSecurityGroupIngress, event_source: ec2.amazonaws.com, event_time: 2026-06-30T01:09:00Z, identity_type: IAMUser, source_ip: 198.51.100.20, user_agent: aws-cli/2.x
- References: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html, https://attack.mitre.org/techniques/T1578/005/

#### CLD-006: Repeated API failures from one actor and source

- Module: `cloudtrail`
- Category: `audit-and-detection`
- Resource: `api_activity/unknown-user@192.0.2.44`
- Evidence: 6 failed API call(s) from unknown-user at 192.0.2.44 within 10 minutes starting 2026-06-30T02:00:00Z.
- Impact: Repeated failed API calls may indicate credential misuse, probing, or brute-force style activity.
- Remediation: Review the source IP, actor, failed API names, and related authentication activity.
- Metadata: actor: unknown-user, error_codes: AccessDenied, UnauthorizedOperation, event_ids: 00000000-0000-4000-8000-000000000006, 00000000-0000-4000-8000-000000000007, 00000000-0000-4000-8000-000000000008, 00000000-0000-4000-8000-000000000009, 00000000-0000-4000-8000-000000000010, 00000000-0000-4000-8000-000000000011, event_names: AssumeRole, DescribeInstances, GetUser, ListBuckets, ListUsers, event_time: 2026-06-30T02:00:00Z, failure_count: 6, first_seen: 2026-06-30T02:00:00Z, last_seen: 2026-06-30T02:08:00Z, source_ip: 192.0.2.44, window_minutes: 10
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
