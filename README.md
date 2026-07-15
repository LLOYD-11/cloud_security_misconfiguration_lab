# Cloud Security Misconfiguration Lab

This project is an offline-first AWS security analysis lab for identifying risky identity, storage, network, and audit-event patterns from JSON evidence.

The goal is to provide practical and explainable security findings without requiring cloud credentials or making changes to a live AWS account.

The repository includes four analyzers, a versioned shared finding contract, a unified CLI, a deterministic sample report, and automated engineering checks across Python 3.10 and 3.13.

## Quick Start

From the repository root, run the complete sample pipeline without installing runtime dependencies:

```bash
python3 -m cloud_security_lab demo --report-date 2026-06-30
```

This writes four versioned finding files and a 28-finding consolidated report under `reports/generated/`. The result should exactly match [`reports/cloud_security_report_sample.md`](reports/cloud_security_report_sample.md).

Install the project in a virtual environment to expose the `cloud-security-lab` command:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/cloud-security-lab --help
```

## Modules

### Module 1: IAM Policy Analyzer

The first module analyzes sample IAM users, identity policies, and trust policies for common cloud security risks:

- Wildcard actions such as `Action: "*"`
- Wildcard resources such as `Resource: "*"`
- Administrator-style access
- Broad S3 permissions
- Sensitive user permissions without an MFA policy guard
- Cross-account trust relationships
- Long-lived access keys in sample user metadata

The analyzer produces terminal findings and exports structured JSON evidence for reporting.

Rule catalog:

| Rule | Risk Pattern |
| --- | --- |
| `IAM-001` | Administrator-style `Action "*"` on `Resource "*"` |
| `IAM-002` | Wildcard action |
| `IAM-003` | Wildcard resource |
| `IAM-004` | Broad S3 write permission |
| `IAM-005` | Sensitive action without MFA condition |
| `IAM-006` | User without MFA enabled |
| `IAM-007` | Long-lived access key |
| `IAM-008` | Cross-account role trust |

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
- Public ACL grants
- Bucket policies that allow `Principal: "*"`
- Missing an explicit bucket encryption configuration beyond the S3 SSE-S3 baseline
- Missing or suspended versioning

Rule catalog:

| Rule | Risk Pattern |
| --- | --- |
| `STO-001` | S3 public access block is incomplete |
| `STO-002` | Bucket ACL grants public access |
| `STO-003` | Bucket policy allows public principal |
| `STO-004` | Bucket lacks an explicit encryption configuration |
| `STO-005` | Bucket versioning is not enabled |

### Module 4: Network Configuration Analyzer

The network analyzer checks sample security group configurations for risky network exposure:

- Protocol-aware sensitive ports open to internet-wide or exceptionally broad public CIDRs
- All inbound ports open to the internet
- Unrestricted outbound traffic to the internet

Rule catalog:

| Rule | Risk Pattern |
| --- | --- |
| `NET-001` | Sensitive port is open to the internet |
| `NET-002` | All inbound ports are open to the internet |
| `NET-003` | Unrestricted outbound traffic is allowed |

### Module 5: CloudTrail-Style Event Detector

The CloudTrail detector checks sample audit events for suspicious cloud API activity:

- Root account console login
- MFA device disabled or deleted
- Successful security group authorization changes
- Successful bucket access changes that can weaken controls
- Successful IAM policy changes that can add access
- Repeated API failures from one actor and source

Duplicate CloudTrail events with the same `eventID` are analyzed once. Failed API calls remain available to the failure-spike detector but are not reported as successful configuration changes.

Rule catalog:

| Rule | Risk Pattern |
| --- | --- |
| `CLD-001` | Root account console login |
| `CLD-002` | MFA device disabled or deleted |
| `CLD-003` | Security group configuration changed |
| `CLD-004` | Bucket access policy changed |
| `CLD-005` | IAM policy configuration changed |
| `CLD-006` | Repeated API failures |

## Unified CLI

Run one analyzer:

```bash
python3 -m cloud_security_lab analyze iam \
  sample_data/iam/sample_iam_environment.json \
  --output reports/generated/iam_findings.json
```

Merge one or more versioned finding files:

```bash
python3 -m cloud_security_lab report \
  --findings reports/generated/iam_findings.json \
  --findings reports/generated/storage_findings.json \
  --findings reports/generated/network_findings.json \
  --findings reports/generated/cloudtrail_findings.json \
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
.venv/bin/mypy cloud_security_lab cloud_findings iam_analyzer storage_analyzer network_analyzer cloudtrail_detector report_generator
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
│   └── cli.py
├── cloud_findings/
│   └── finding.py
├── cloudtrail_detector/
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
│   └── *-environment-v1.0.schema.json
├── sample_data/
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
│   └── known-limitations.md
├── tests/
│   ├── test_contracts.py
│   └── test_legacy_clis.py
├── LICENSE
└── .gitignore
```

## Safety Boundary

This project operates on offline sample data. Do not connect future collectors to a real cloud account unless the account is owned by you or you have explicit permission to assess it.
