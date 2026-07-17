# Cloud Security Misconfiguration Lab

This project is an offline-first AWS security analysis lab for identifying risky identity, storage, network, and audit-event patterns from exported evidence.

The goal is to provide practical and explainable security findings without requiring cloud credentials or making changes to a live AWS account.

The repository includes four analyzers, native AWS IAM, S3, EC2 security-group, and CloudTrail input normalization, versioned finding and incident contracts, a unified CLI, a deterministic sample report, and automated engineering checks across Python 3.10 and 3.13.

## Quick Start

From the repository root, run the complete sample pipeline without installing runtime dependencies:

```bash
python3 -m cloud_security_lab demo --report-date 2026-06-30
```

This writes four versioned finding files, one correlated incident file, and a 39-finding consolidated report under `reports/generated/`. The result should exactly match [`reports/cloud_security_report_sample.md`](reports/cloud_security_report_sample.md).

Install the project in a virtual environment to expose the `cloud-security-lab` command:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/cloud-security-lab --help
```

## Modules

### Module 1: IAM Policy Analyzer

The first module analyzes sample IAM users, identity policies, and trust policies for common cloud security risks:

- Full, service, and partial action wildcards such as `*`, `iam:*`, and `iam:Get*`
- Unscoped resources and broad `NotAction` or `NotResource` complements
- Administrator-style access
- Broad S3 permissions
- Sensitive user permissions without an MFA policy guard
- Public and cross-account role trust, with recognized trust-condition guardrails
- Direct and group policy exposure
- Long-lived and stale credentials, root credentials, and ineffective permissions boundaries

The analyzer produces terminal findings and exports structured JSON evidence for reporting.

IAM input can use either the documented simplified environment contract or native AWS `GetAccountAuthorizationDetails` plus credential-report exports. Native input preserves direct policies, IAM groups and members, role trust, permissions boundaries, console-password posture, root credentials, and access-key age and usage before applying the same detection rules.

Rule catalog:

| Rule | Risk Pattern |
| --- | --- |
| `IAM-001` | Administrator-style `Action "*"` on `Resource "*"` |
| `IAM-002` | Full, service, or partial wildcard action |
| `IAM-003` | Unscoped wildcard resource |
| `IAM-004` | Broad S3 write permission |
| `IAM-005` | Sensitive action without MFA condition |
| `IAM-006` | Console-enabled user without MFA |
| `IAM-007` | Long-lived access key |
| `IAM-008` | Public or cross-account role trust |
| `IAM-009` | Broad allow using `NotAction` |
| `IAM-010` | Broad allow using `NotResource` |
| `IAM-011` | Stale active access key |
| `IAM-012` | Stale console password |
| `IAM-013` | Active root access key |
| `IAM-014` | Root password without MFA |
| `IAM-015` | Unrestricted permissions boundary |

### Module 2: Risk Report Generator

The report generator reads one or more finding JSON files and creates a consolidated Markdown risk report.

All analyzers should emit the same finding schema:

| Field | Purpose |
| --- | --- |
| `rule_id` | Stable detection rule identifier |
| `severity` | `critical`, `high`, `medium`, `low`, or `info` |
| `module` | Analyzer module name, such as `iam` |
| `category` | Security domain, such as `identity-and-access` |
| `resource_type` | Affected resource type |
| `resource_id` | Affected resource name or identifier |
| `title` | Short finding title |
| `evidence` | Concrete observed evidence |
| `impact` | Why the issue matters |
| `remediation` | Recommended fix |
| `references` | Optional reference links |
| `metadata` | Optional module-specific details |

### Module 3: Storage Exposure Analyzer

The storage analyzer checks sample S3-style bucket configurations for common exposure and resilience risks:

- Incomplete S3 Block Public Access controls
- Public ACL grants that remain effective under Block Public Access and Object Ownership
- Bucket policies with unrestricted `Principal: "*"` or broad `NotPrincipal`
- Policy conditions that do not create an AWS-recognized fixed-value access boundary
- ACL-enabled Object Ownership modes
- Missing an explicit bucket encryption configuration beyond the S3 SSE-S3 baseline
- Missing or suspended versioning

Storage input can use either the simplified environment contract or a versioned native evidence bundle containing `ListBuckets`, account and bucket Public Access Block, Object Ownership, ACL, policy, default encryption, and versioning responses.

Public ACL and bucket-policy exposure findings account for `BucketOwnerEnforced`, effective `IgnorePublicAcls`, and effective `RestrictPublicBuckets` rather than reporting blocked access paths as active exposure. Wildcard-principal policies are treated as non-public only when a supported positive condition operator fixes access to an AWS-recognized organization, account, source ARN, VPC, VPC endpoint, data access point, or sufficiently narrow source network.

In this module, non-public means that a statement is constrained under the S3 Block Public Access model; it does not mean that the named external account, organization, network, or service is automatically trusted.

Rule catalog:

| Rule | Risk Pattern |
| --- | --- |
| `STO-001` | S3 public access block is incomplete |
| `STO-002` | Bucket ACL grants public access |
| `STO-003` | Bucket policy allows an effectively public principal |
| `STO-004` | Bucket lacks an explicit encryption configuration |
| `STO-005` | Bucket versioning is not enabled |
| `STO-006` | Bucket ACLs remain enabled by Object Ownership |

### Module 4: Network Configuration Analyzer

The network analyzer checks sample security group configurations for risky network exposure:

- Protocol-aware exposure across 20 remote-administration, database, data-service, and control-plane endpoints
- All inbound ports open to the internet
- Unrestricted outbound traffic to the internet
- Optional, direction-specific reachability evidence that distinguishes a permitted security-group path from reported end-to-end connectivity

Network input can use either the simplified environment contract or a complete native EC2 `DescribeSecurityGroups` response. Native normalization validates account, VPC, security-group, peering, protocol, port, and CIDR evidence before applying the same rules. Prefix-list and security-group targets are preserved with visible warnings but are not resolved into public reachability.

An optional versioned reachability context can mark ingress and egress as `reachable`, `not_reachable`, or `inconclusive`, with an explicit scope, assessment method, timestamp, evidence, and related resource IDs. Missing context is recorded as `not_assessed`. A valid `not_reachable` assessment lowers severity by one level but never suppresses the permissive configuration finding; `reachable`, `inconclusive`, and `not_assessed` retain the service default. The lab validates and reports this supplied context but does not independently reproduce AWS path analysis.

Rule catalog:

| Rule | Risk Pattern |
| --- | --- |
| `NET-001` | Sensitive service port permits traffic from an internet-wide or broad public CIDR |
| `NET-002` | All inbound ports are open to the internet |
| `NET-003` | Unrestricted outbound traffic is allowed |

See the [Network analyzer documentation](network_analyzer/README.md) for the complete service catalog and reachability semantics.

### Module 5: CloudTrail-Style Event Detector

The CloudTrail detector checks sample audit events for suspicious cloud API activity:

- Root account console login
- MFA device disabled or deleted
- Successful security group authorization changes
- Successful bucket access changes that can weaken controls
- Successful IAM policy changes that can add access
- Repeated API failures from one actor and source
- IAM user console logins explicitly recorded without MFA
- Persistent credential creation and role trust-policy changes
- Audit or threat-detection controls being disabled
- KMS keys being disabled or scheduled for deletion

Duplicate CloudTrail events with the same `eventID` are analyzed once. Failed API calls remain available to the failure-spike detector but are not reported as successful configuration changes.

CloudTrail input can use either the simplified event contract or one or more native `Records` log files in JSON or gzip format. Native normalization validates version 1.x records, UTC timestamps, identity and account context, and event GUIDs before merging files. Identical duplicate events are skipped with a warning; conflicting records sharing an ID stop analysis.

Rule catalog:

| Rule | Risk Pattern |
| --- | --- |
| `CLD-001` | Root account console login |
| `CLD-002` | MFA device disabled or deleted |
| `CLD-003` | Security group configuration changed |
| `CLD-004` | Bucket access policy changed |
| `CLD-005` | IAM policy configuration changed |
| `CLD-006` | Repeated API failures |
| `CLD-007` | IAM user console login without MFA |
| `CLD-008` | Persistent cloud credential created |
| `CLD-009` | Role trust policy changed |
| `CLD-010` | Audit or threat-detection control disabled |
| `CLD-011` | KMS key disabled or scheduled for deletion |

The detector also correlates eligible findings from the same actor and source into versioned incidents. The default 30-minute window, qualification rules, deterministic IDs, confidence model, and limitations are documented in [CloudTrail incident correlation](docs/incident-correlation.md).

## Unified CLI

Run one analyzer:

```bash
python3 -m cloud_security_lab analyze iam \
  sample_data/iam/sample_iam_environment.json \
  --output reports/generated/iam_findings.json
```

Analyze native AWS IAM exports without connecting the lab to an account:

```bash
python3 -m cloud_security_lab analyze iam \
  sample_data/aws/iam/account_authorization_details.json \
  --input-format aws \
  --credential-report sample_data/aws/iam/credential_report.csv \
  --as-of 2026-06-30 \
  --normalized-output reports/generated/normalized_iam_environment.json \
  --output reports/generated/iam_findings.json
```

See [Native AWS inputs](docs/native-aws-inputs.md) for evidence collection, validation behavior, and limitations.

Analyze the bundled native AWS S3 evidence:

```bash
python3 -m cloud_security_lab analyze storage \
  sample_data/aws/s3/s3_security_evidence_bundle.json \
  --input-format aws \
  --normalized-output reports/generated/normalized_storage_environment.json \
  --output reports/generated/storage_findings.json
```

Analyze the bundled native EC2 security-group response:

```bash
python3 -m cloud_security_lab analyze network \
  sample_data/aws/ec2/describe_security_groups.json \
  --input-format aws \
  --reachability-context sample_data/aws/ec2/network_reachability_context.json \
  --normalized-output reports/generated/normalized_network_environment.json \
  --output reports/generated/network_findings.json
```

Analyze the bundled native CloudTrail JSON and gzip files:

```bash
python3 -m cloud_security_lab analyze cloudtrail \
  sample_data/aws/cloudtrail/111122223333_CloudTrail_20260630T0200Z_part1.json \
  sample_data/aws/cloudtrail/111122223333_CloudTrail_20260630T0300Z_part2.json.gz \
  --input-format aws \
  --normalized-output reports/generated/normalized_cloudtrail_environment.json \
  --output reports/generated/cloudtrail_findings.json \
  --incidents-output reports/generated/cloudtrail_incidents.json
```

Merge one or more versioned finding files:

```bash
python3 -m cloud_security_lab report \
  --findings reports/generated/iam_findings.json \
  --findings reports/generated/storage_findings.json \
  --findings reports/generated/network_findings.json \
  --findings reports/generated/cloudtrail_findings.json \
  --incidents reports/generated/cloudtrail_incidents.json \
  --report-date 2026-06-30 \
  --output reports/generated/cloud_security_report.md
```

The installed `cloud-security-lab` command exposes the same `analyze`, `report`, and `demo` subcommands. The explicit report date makes sample output reproducible; omit `--report-date` to use the current local date.

## Compatibility Entrypoints

The original module scripts remain supported:

```bash
python3 iam_analyzer/analyzer.py sample_data/iam/sample_iam_environment.json
python3 storage_analyzer/analyzer.py sample_data/storage/sample_storage_environment.json
python3 network_analyzer/analyzer.py sample_data/network/sample_network_environment.json
python3 cloudtrail_detector/detector.py sample_data/cloudtrail/sample_cloudtrail_events.json
```

## Project Documentation

- [Upgrade roadmap](ROADMAP.md)
- [Data contracts](docs/data-contracts.md)
- [Native AWS inputs](docs/native-aws-inputs.md)
- [Engineering checks](docs/engineering.md)
- [Known limitations](docs/known-limitations.md)
- [Change log](CHANGELOG.md)

## Requirements

Runtime: Python 3.10 or later. The analyzers and unified CLI have no third-party runtime dependencies.

Development and contract checks use optional tools declared in `pyproject.toml`:

```bash
.venv/bin/python -m pip install -e ".[dev]"
```

## Quality Checks

```bash
.venv/bin/ruff check .
.venv/bin/mypy cloud_security_lab cloud_findings cloud_incidents iam_analyzer storage_analyzer network_analyzer cloudtrail_detector report_generator
.venv/bin/coverage run -m unittest discover
.venv/bin/coverage report
```

The coverage gate is 85% with branch coverage enabled. GitHub Actions also rebuilds the package and verifies the deterministic end-to-end report on Python 3.10 and 3.13.

## Project Structure

```text
cloud_security_misconfiguration_lab/
├── .github/workflows/ci.yml
├── README.md
├── ROADMAP.md
├── CHANGELOG.md
├── pyproject.toml
├── cloud_security_lab/
│   ├── __main__.py
│   ├── cli.py
│   └── normalizers/
│       ├── cloudtrail.py
│       ├── common.py
│       ├── ec2.py
│       ├── iam.py
│       ├── network_context.py
│       └── s3.py
├── cloud_findings/
│   └── finding.py
├── cloud_incidents/
│   └── incident.py
├── cloudtrail_detector/
│   ├── correlation.py
│   ├── detector.py
│   ├── README.md
│   └── test_detector.py
├── iam_analyzer/
│   ├── analyzer.py
│   ├── README.md
│   └── test_analyzer.py
├── network_analyzer/
│   ├── analyzer.py
│   ├── README.md
│   └── test_analyzer.py
├── report_generator/
│   ├── generate_report.py
│   ├── README.md
│   └── test_generate_report.py
├── reports/
│   └── cloud_security_report_sample.md
├── schemas/
│   ├── findings-v1.0.schema.json
│   ├── incidents-v1.0.schema.json
│   ├── aws-cloudtrail-records-v1.0.schema.json
│   ├── aws-iam-authorization-details-v1.0.schema.json
│   ├── aws-ec2-describe-security-groups-v1.0.schema.json
│   ├── network-reachability-context-v1.0.schema.json
│   ├── aws-s3-evidence-bundle-v1.0.schema.json
│   └── *-environment-v1.0.schema.json
├── sample_data/
│   ├── aws/cloudtrail/
│   │   ├── 111122223333_CloudTrail_20260630T0200Z_part1.json
│   │   └── 111122223333_CloudTrail_20260630T0300Z_part2.json.gz
│   ├── aws/iam/
│   │   ├── account_authorization_details.json
│   │   └── credential_report.csv
│   ├── aws/ec2/
│   │   ├── describe_security_groups.json
│   │   └── network_reachability_context.json
│   ├── aws/s3/
│   │   └── s3_security_evidence_bundle.json
│   ├── cloudtrail/
│   │   └── sample_cloudtrail_events.json
│   ├── iam/
│   │   └── sample_iam_environment.json
│   ├── network/
│   │   └── sample_network_environment.json
│   └── storage/
│       └── sample_storage_environment.json
├── storage_analyzer/
│   ├── analyzer.py
│   ├── README.md
│   └── test_analyzer.py
├── docs/
│   ├── data-contracts.md
│   ├── engineering.md
│   ├── incident-correlation.md
│   ├── native-aws-inputs.md
│   └── known-limitations.md
├── tests/
│   ├── test_contracts.py
│   └── test_legacy_clis.py
├── LICENSE
└── .gitignore
```

## Safety Boundary

This project operates on offline sample data. Do not connect future collectors to a real cloud account unless the account is owned by you or you have explicit permission to assess it.
