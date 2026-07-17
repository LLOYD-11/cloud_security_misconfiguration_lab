# Detection Rule Catalog

Schema version: 1.0

Confidence describes how directly the available evidence supports the rule condition. It does not establish malicious intent.

`direct` means the detector condition substantially matches the control or technique. `related` means the mapping provides useful context but is not equivalent coverage.

## Framework Scope

| Framework | Version | Source |
| --- | --- | --- |
| AWS Security Hub CSPM | live | [Authoritative source](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html) |
| CIS AWS Foundations Benchmark | 5.0.0 | [Authoritative source](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html) |
| MITRE ATT&CK Enterprise | live | [Authoritative source](https://attack.mitre.org/) |

AWS Security Hub and MITRE ATT&CK mappings track their live public references. CIS mappings are pinned to the AWS-published v5.0.0 crosswalk; newer CIS releases are not assigned control IDs by inference.

## Iam

| Rule | Title | Default / Allowed Severity | Confidence | Control Mappings |
| --- | --- | --- | --- | --- |
| `IAM-001` | Administrator-style wildcard permission | critical / critical | high | AWS Security Hub CSPM IAM.1 (direct) |
| `IAM-002` | Wildcard action allowed | medium / medium, high | high | AWS Security Hub CSPM IAM.21 (related) |
| `IAM-003` | Wildcard resource scope | medium / medium | high | AWS Security Hub CSPM IAM.1 (related) |
| `IAM-004` | Broad S3 write permission | high / high | medium | MITRE ATT&CK Enterprise T1485 (related) |
| `IAM-005` | Sensitive action without MFA condition | medium / medium | medium | AWS Security Hub CSPM IAM.5 (related) |
| `IAM-006` | User MFA is disabled | medium / medium | high | AWS Security Hub CSPM IAM.5 (direct)<br>CIS AWS Foundations Benchmark 1.9 (direct) |
| `IAM-007` | Long-lived access key | medium / medium | high | AWS Security Hub CSPM IAM.3 (direct)<br>CIS AWS Foundations Benchmark 1.13 (direct) |
| `IAM-008` | Broad or external role trust | high / medium, high, critical | medium | MITRE ATT&CK Enterprise T1199 (related) |
| `IAM-009` | Broad allow uses NotAction | medium / medium, high | high | AWS Security Hub CSPM IAM.1 (related) |
| `IAM-010` | Broad allow uses NotResource | medium / medium, high | high | AWS Security Hub CSPM IAM.1 (related) |
| `IAM-011` | Stale active access key | medium / medium | high | AWS Security Hub CSPM IAM.22 (related)<br>CIS AWS Foundations Benchmark 1.11 (related) |
| `IAM-012` | Stale console password | medium / medium | high | AWS Security Hub CSPM IAM.22 (related)<br>CIS AWS Foundations Benchmark 1.11 (related) |
| `IAM-013` | Root account has an active access key | critical / critical | high | AWS Security Hub CSPM IAM.4 (direct)<br>CIS AWS Foundations Benchmark 1.3 (direct) |
| `IAM-014` | Root account MFA is disabled | critical / critical | high | AWS Security Hub CSPM IAM.9 (direct)<br>CIS AWS Foundations Benchmark 1.4 (direct) |
| `IAM-015` | Permissions boundary does not constrain access | medium / medium | high | AWS Security Hub CSPM IAM.1 (related) |

### IAM-001: Administrator-style wildcard permission

Detects an Allow statement that grants every action against every resource.

Confidence basis: The analyzer observes an explicit Allow with both Action and Resource set to a full wildcard.

- [AWS Security Hub CSPM IAM.1 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1): Both checks identify customer-managed IAM policy statements that allow all actions on all resources.

### IAM-002: Wildcard action allowed

Detects wildcard patterns in allowed IAM actions, including service-wide and partial wildcards.

Confidence basis: The action pattern is explicit policy evidence; severity rises for full or service-wide wildcards.

- [AWS Security Hub CSPM IAM.21 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-21): The lab also flags partial wildcard action patterns, so its condition is broader than the Security Hub control.

### IAM-003: Wildcard resource scope

Detects allowed actions that apply to every resource.

Confidence basis: The Resource wildcard is explicit, although some AWS actions do not support resource-level scoping.

- [AWS Security Hub CSPM IAM.1 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1): Wildcard resource scope contributes to administrative breadth, but this rule can trigger without Action being a full wildcard.

### IAM-004: Broad S3 write permission

Detects write-capable S3 actions granted across wildcard bucket or object resources.

Confidence basis: The policy grants broad S3 write capability, but effective access can still be reduced by boundaries, resource policies, or explicit denies.

- [MITRE ATT&CK Enterprise T1485 (related)](https://attack.mitre.org/techniques/T1485/): Broad S3 write and delete capability can enable destructive impact, but the rule identifies permission rather than observed destruction.

### IAM-005: Sensitive action without MFA condition

Detects privileged user or group permissions that do not require an MFA-present condition.

Confidence basis: The statement lacks an MFA condition, but other identity controls or session policies may still require MFA.

- [AWS Security Hub CSPM IAM.5 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-5): Both concern MFA protection for IAM users, while this rule evaluates policy conditions rather than credential-report enrollment.

### IAM-006: User MFA is disabled

Detects an IAM user with console-password access and no registered MFA device.

Confidence basis: Credential-report evidence directly states password and MFA status when native AWS input is used.

- [AWS Security Hub CSPM IAM.5 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-5): The rule and control evaluate the same console-password and MFA enrollment condition.
- [CIS AWS Foundations Benchmark 1.9 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html): The analyzer directly evaluates the credential-report fields used by this benchmark recommendation.

### IAM-007: Long-lived access key

Detects an active IAM access key older than the analyzer rotation threshold.

Confidence basis: The active status and key age are derived directly from credential-report timestamps.

- [AWS Security Hub CSPM IAM.3 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-3): The lab uses the same 90-day rotation threshold as this Security Hub control.
- [CIS AWS Foundations Benchmark 1.13 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html): The analyzer and benchmark recommendation use the same 90-day access-key rotation threshold.

### IAM-008: Broad or external role trust

Detects role trust policies that allow public or cross-account principals, with severity adjusted for recognized guardrails.

Confidence basis: The external principal is explicit, but effective assumability also depends on caller permissions, conditions, organization boundaries, and external IDs.

- [MITRE ATT&CK Enterprise T1199 (related)](https://attack.mitre.org/techniques/T1199/): Cross-account role trust can expose a trusted access path, but the rule does not establish that an adversary has compromised the trusted party.

### IAM-009: Broad allow uses NotAction

Detects Allow statements that grant the complement of an excluded action list.

Confidence basis: NotAction is explicit policy syntax; severity rises when the statement also applies to every resource.

- [AWS Security Hub CSPM IAM.1 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1): An Allow with NotAction can approach administrative breadth, but it is not necessarily equivalent to allowing every action.

### IAM-010: Broad allow uses NotResource

Detects Allow statements that apply to every applicable resource except an exclusion list.

Confidence basis: NotResource is explicit policy syntax; severity rises for sensitive or wildcard action sets.

- [AWS Security Hub CSPM IAM.1 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1): A broad NotResource allow can undermine least privilege, but it does not always provide full administrative access.

### IAM-011: Stale active access key

Detects an active access key that has not been used within the analyzer inactivity threshold.

Confidence basis: Key status and last-used age come directly from credential-report evidence.

- [AWS Security Hub CSPM IAM.22 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-22): Both detect unused active credentials, but the lab uses a 90-day threshold while the Security Hub parameter can differ.
- [CIS AWS Foundations Benchmark 1.11 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html): The benchmark uses 45 days, while this analyzer intentionally uses a 90-day inactivity threshold.

### IAM-012: Stale console password

Detects an active IAM console password that has not been used within the analyzer inactivity threshold.

Confidence basis: Password status and last-used age come directly from credential-report evidence.

- [AWS Security Hub CSPM IAM.22 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-22): Both detect unused IAM credentials, but evaluation thresholds and evidence collection can differ.
- [CIS AWS Foundations Benchmark 1.11 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html): The benchmark uses 45 days, while this analyzer intentionally uses a 90-day inactivity threshold.

### IAM-013: Root account has an active access key

Detects an active programmatic access key for the AWS account root user.

Confidence basis: Credential-report evidence directly identifies active root access-key slots.

- [AWS Security Hub CSPM IAM.4 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-4): The rule and control evaluate the same root access-key condition.
- [CIS AWS Foundations Benchmark 1.3 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html): The analyzer directly detects active root access keys from the credential report.

### IAM-014: Root account MFA is disabled

Detects an AWS root user with an active console password and no MFA device.

Confidence basis: Credential-report evidence directly states root password and MFA status.

- [AWS Security Hub CSPM IAM.9 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-9): The rule and control evaluate the same root MFA condition without claiming hardware-MFA coverage.
- [CIS AWS Foundations Benchmark 1.4 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html): The analyzer directly evaluates root MFA enrollment from credential-report evidence.

### IAM-015: Permissions boundary does not constrain access

Detects a permissions boundary that itself allows every action against every resource.

Confidence basis: The boundary document explicitly allows full wildcard access, so it does not lower the maximum permission set.

- [AWS Security Hub CSPM IAM.1 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1): The wildcard syntax matches administrative breadth, but a permissions boundary limits rather than directly grants effective permissions.

## Storage

| Rule | Title | Default / Allowed Severity | Confidence | Control Mappings |
| --- | --- | --- | --- | --- |
| `STO-001` | S3 public access block is incomplete | high / high | high | AWS Security Hub CSPM S3.1 (related)<br>AWS Security Hub CSPM S3.8 (direct)<br>CIS AWS Foundations Benchmark 2.1.4 (direct) |
| `STO-002` | Bucket ACL grants public access | critical / critical | high | AWS Security Hub CSPM S3.2 (related)<br>AWS Security Hub CSPM S3.3 (related)<br>CIS AWS Foundations Benchmark 2.1.4 (related) |
| `STO-003` | Bucket policy allows an effectively public principal | critical / critical | medium | AWS Security Hub CSPM S3.2 (related)<br>AWS Security Hub CSPM S3.3 (related)<br>AWS Security Hub CSPM S3.8 (direct)<br>CIS AWS Foundations Benchmark 2.1.4 (direct) |
| `STO-004` | Bucket lacks an explicit encryption configuration | low / low | high | AWS Security Hub CSPM S3.17 (related) |
| `STO-005` | Bucket versioning is not enabled | medium / medium | high | AWS Security Hub CSPM S3.14 (direct) |
| `STO-006` | Bucket access control lists remain enabled | medium / medium | high | AWS Security Hub CSPM S3.12 (direct) |

### STO-001: S3 public access block is incomplete

Detects an S3 bucket with one or more Block Public Access controls disabled or missing.

Confidence basis: The rule directly evaluates all four bucket-level Block Public Access booleans.

- [AWS Security Hub CSPM S3.1 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-1): Both evaluate S3 Block Public Access, but Security Hub can incorporate account-level settings that this bucket evidence does not model.
- [AWS Security Hub CSPM S3.8 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-8): The rule checks whether the bucket-level public-access protections required by this control are all enabled.
- [CIS AWS Foundations Benchmark 2.1.4 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html): The analyzer directly evaluates the bucket-level configuration named by this benchmark recommendation.

### STO-002: Bucket ACL grants public access

Detects an effective public or broadly authenticated S3 ACL grant.

Confidence basis: The ACL grantee is explicitly public and the analyzer confirms that ACLs are neither ignored nor disabled by Object Ownership.

- [AWS Security Hub CSPM S3.2 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-2): A public ACL can grant read access, but this rule also detects other public ACL permissions.
- [AWS Security Hub CSPM S3.3 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-3): A public ACL can grant write access, but this rule also detects public read or metadata permissions.
- [CIS AWS Foundations Benchmark 2.1.4 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html): Public ACL exposure is a condition the benchmark's Block Public Access recommendation is intended to prevent.

### STO-003: Bucket policy allows an effectively public principal

Detects an S3 bucket-policy Allow whose broad principal lacks an AWS-recognized fixed-value guardrail.

Confidence basis: The policy is public under modeled S3 policy rules, but account-level Block Public Access and unmodeled policy context can affect runtime exposure.

- [AWS Security Hub CSPM S3.2 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-2): A public bucket policy can grant read access, while this rule also covers non-read actions.
- [AWS Security Hub CSPM S3.3 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-3): A public bucket policy can grant write access, while this rule also covers non-write actions.
- [AWS Security Hub CSPM S3.8 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-8): The rule identifies the effective public policy exposure that S3 Block Public Access is designed to prevent.
- [CIS AWS Foundations Benchmark 2.1.4 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html): The detected public policy is directly addressed by enabling and enforcing Block Public Access.

### STO-004: Bucket lacks an explicit encryption configuration

Detects the absence of an explicit bucket-level default encryption configuration.

Confidence basis: The configuration absence is explicit in the evidence, while the low severity acknowledges S3 baseline SSE-S3 encryption.

- [AWS Security Hub CSPM S3.17 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-17): The rule identifies missing explicit encryption configuration but does not require KMS or claim that objects are stored unencrypted.

### STO-005: Bucket versioning is not enabled

Detects an S3 bucket whose versioning status is disabled or suspended.

Confidence basis: The bucket versioning state is directly represented in the normalized evidence.

- [AWS Security Hub CSPM S3.14 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-14): The rule and control evaluate the same bucket versioning condition.

### STO-006: Bucket access control lists remain enabled

Detects an S3 Object Ownership mode that leaves ACL-based access control active.

Confidence basis: The Object Ownership setting directly determines whether ACLs can affect authorization.

- [AWS Security Hub CSPM S3.12 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-12): The rule detects the ACL-enabled ownership modes that this control recommends replacing with BucketOwnerEnforced.

## Network

| Rule | Title | Default / Allowed Severity | Confidence | Control Mappings |
| --- | --- | --- | --- | --- |
| `NET-001` | Sensitive service port permits public traffic | high / medium, high, critical | medium | AWS Security Hub CSPM EC2.18 (related)<br>AWS Security Hub CSPM EC2.19 (related)<br>AWS Security Hub CSPM EC2.53 (related)<br>AWS Security Hub CSPM EC2.54 (related)<br>CIS AWS Foundations Benchmark 5.3 (related)<br>CIS AWS Foundations Benchmark 5.4 (related) |
| `NET-002` | All inbound ports permit public traffic | critical / high, critical | medium | AWS Security Hub CSPM EC2.18 (direct)<br>AWS Security Hub CSPM EC2.19 (direct) |
| `NET-003` | Security group permits unrestricted outbound traffic | medium / low, medium | medium | MITRE ATT&CK Enterprise T1041 (related) |

### NET-001: Sensitive service port permits public traffic

Detects public IPv4 or IPv6 ingress to cataloged administrative, database, or control-plane service ports.

Confidence basis: The security-group source and port are explicit, but end-to-end exposure depends on optional reachability context and attached resources.

- [AWS Security Hub CSPM EC2.18 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18): Both flag unrestricted ingress, while this rule targets a curated sensitive-service catalog and supports broad public CIDRs.
- [AWS Security Hub CSPM EC2.19 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-19): The rule covers high-risk ports and additional service categories, with context-sensitive severity.
- [AWS Security Hub CSPM EC2.53 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-53): The rule includes public IPv4 access to SSH and RDP, but also evaluates other sensitive services.
- [AWS Security Hub CSPM EC2.54 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-54): The rule includes public IPv6 access to SSH and RDP, but also evaluates other sensitive services.
- [CIS AWS Foundations Benchmark 5.3 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html): The analyzer covers the benchmark's IPv4 SSH and RDP cases plus additional public CIDRs and services.
- [CIS AWS Foundations Benchmark 5.4 (related)](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html): The analyzer covers the benchmark's IPv6 SSH and RDP cases plus additional public networks and services.

### NET-002: All inbound ports permit public traffic

Detects a security-group ingress rule that allows every port from a public IPv4 or IPv6 network.

Confidence basis: The all-port public rule is explicit, but actual internet reachability depends on routing, attached resources, and optional path evidence.

- [AWS Security Hub CSPM EC2.18 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18): An all-port public rule is a direct unrestricted-ingress condition.
- [AWS Security Hub CSPM EC2.19 (direct)](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-19): Allowing all ports necessarily includes every high-risk port evaluated by the control.

### NET-003: Security group permits unrestricted outbound traffic

Detects all-protocol, all-port egress from a security group to a public IPv4 or IPv6 network.

Confidence basis: The egress permission is explicit, but an exploitable exfiltration path depends on workload compromise and end-to-end network routing.

- [MITRE ATT&CK Enterprise T1041 (related)](https://attack.mitre.org/techniques/T1041/): Unrestricted egress can enable exfiltration or command-and-control traffic, but the rule does not observe data transfer.

## Cloudtrail

| Rule | Title | Default / Allowed Severity | Confidence | Control Mappings |
| --- | --- | --- | --- | --- |
| `CLD-001` | Root account console login | critical / critical | high | MITRE ATT&CK Enterprise T1078.004 (related) |
| `CLD-002` | MFA device was disabled or deleted | high / high | high | MITRE ATT&CK Enterprise T1098 (direct) |
| `CLD-003` | Security group configuration changed | medium / medium | high | MITRE ATT&CK Enterprise T1578.005 (direct) |
| `CLD-004` | Bucket access policy changed | high / high | high | MITRE ATT&CK Enterprise T1565 (related) |
| `CLD-005` | IAM policy configuration changed | high / high | high | MITRE ATT&CK Enterprise T1098 (direct) |
| `CLD-006` | Repeated API failures from one actor and source | medium / medium | medium | MITRE ATT&CK Enterprise T1110 (related) |
| `CLD-007` | IAM user console login did not use MFA | high / high | high | MITRE ATT&CK Enterprise T1078.004 (related) |
| `CLD-008` | Persistent cloud credential was created | high / high | high | MITRE ATT&CK Enterprise T1098.001 (direct) |
| `CLD-009` | Role trust policy was changed | high / high | high | MITRE ATT&CK Enterprise T1098.003 (direct) |
| `CLD-010` | Audit or threat-detection control was disabled | high / high, critical | high | MITRE ATT&CK Enterprise T1685 (direct)<br>MITRE ATT&CK Enterprise T1685.002 (related) |
| `CLD-011` | KMS key was disabled or scheduled for deletion | high / high, critical | high | MITRE ATT&CK Enterprise T1485 (related) |

### CLD-001: Root account console login

Detects a successful AWS ConsoleLogin event performed by the root identity.

Confidence basis: CloudTrail explicitly records the successful root identity type and ConsoleLogin event.

- [MITRE ATT&CK Enterprise T1078.004 (related)](https://attack.mitre.org/techniques/T1078/004/): Root console use can represent use of a valid cloud account, but the event alone does not prove credential compromise.

### CLD-002: MFA device was disabled or deleted

Detects a successful API event that deactivates or deletes an IAM MFA device.

Confidence basis: The successful CloudTrail event directly records an MFA defense being removed.

- [MITRE ATT&CK Enterprise T1098 (direct)](https://attack.mitre.org/techniques/T1098/): Removing MFA changes an account security property in a way that can support persistence or continued access.

### CLD-003: Security group configuration changed

Detects successful CloudTrail events that add, remove, or modify security-group rules.

Confidence basis: The successful event directly records a cloud network-control modification, though the resulting exposure requires separate analysis.

- [MITRE ATT&CK Enterprise T1578.005 (direct)](https://attack.mitre.org/techniques/T1578/005/): Changing security-group rules is a direct modification of cloud compute networking configuration.

### CLD-004: Bucket access policy changed

Detects successful changes to S3 bucket policy or public-access settings.

Confidence basis: The successful CloudTrail event directly records an S3 access-control change, while the resulting policy effect requires configuration analysis.

- [MITRE ATT&CK Enterprise T1565 (related)](https://attack.mitre.org/techniques/T1565/): Changing bucket access policy can enable later data manipulation or exposure, but the event does not itself show data modification.

### CLD-005: IAM policy configuration changed

Detects successful IAM policy creation, attachment, version, or inline-policy changes.

Confidence basis: The successful event directly records a permission-policy change, while its privilege impact requires policy-diff analysis.

- [MITRE ATT&CK Enterprise T1098 (direct)](https://attack.mitre.org/techniques/T1098/): IAM policy changes can alter account or role permissions to support persistence or privilege escalation.

### CLD-006: Repeated API failures from one actor and source

Detects a threshold burst of failed AWS API calls grouped by actor and source IP within a sliding time window.

Confidence basis: The failure burst is measured directly, but benign automation errors and permission drift can produce the same pattern.

- [MITRE ATT&CK Enterprise T1110 (related)](https://attack.mitre.org/techniques/T1110/): Repeated failures can indicate credential guessing or probing, but the detector also includes non-authentication API errors.

### CLD-007: IAM user console login did not use MFA

Detects a successful IAM-user ConsoleLogin event whose additional event data records MFA as unused.

Confidence basis: CloudTrail directly records both the successful IAM-user login and MFAUsed value.

- [MITRE ATT&CK Enterprise T1078.004 (related)](https://attack.mitre.org/techniques/T1078/004/): A password-only console login can reflect use of a valid cloud account, but the event alone does not establish adversary control.

### CLD-008: Persistent cloud credential was created

Detects successful creation of IAM access keys, login profiles, signing certificates, or service-specific credentials.

Confidence basis: The successful event directly records creation of a durable authentication credential.

- [MITRE ATT&CK Enterprise T1098.001 (direct)](https://attack.mitre.org/techniques/T1098/001/): The event creates an additional credential that can preserve cloud account access.

### CLD-009: Role trust policy was changed

Detects a successful UpdateAssumeRolePolicy event.

Confidence basis: The successful event directly records a role trust-policy modification.

- [MITRE ATT&CK Enterprise T1098.003 (direct)](https://attack.mitre.org/techniques/T1098/003/): Changing a role trust relationship can grant a new principal access through the cloud role.

### CLD-010: Audit or threat-detection control was disabled

Detects successful events that stop, delete, or disable CloudTrail, Config, VPC Flow Logs, Security Hub, or GuardDuty controls.

Confidence basis: The successful event directly records a monitoring or detection control being weakened; severity rises for the most disruptive actions.

- [MITRE ATT&CK Enterprise T1685 (direct)](https://attack.mitre.org/techniques/T1685/): The detector directly observes successful actions that disable cloud logging, monitoring, or threat-detection tooling.
- [MITRE ATT&CK Enterprise T1685.002 (related)](https://attack.mitre.org/techniques/T1685/002/): The sub-technique precisely describes the logging events covered by this broader rule, but not every supported threat-detection event.

### CLD-011: KMS key was disabled or scheduled for deletion

Detects a successful DisableKey or ScheduleKeyDeletion event for an AWS KMS key.

Confidence basis: The successful event directly records KMS key disruption; scheduled deletion raises severity because it can make data unrecoverable.

- [MITRE ATT&CK Enterprise T1485 (related)](https://attack.mitre.org/techniques/T1485/): Disabling or deleting a KMS key can deny access to dependent encrypted data, but impact depends on timing, recovery, and key dependencies.
