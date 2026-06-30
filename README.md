# Cloud Security Misconfiguration Lab

This project is an offline-first cloud security lab for identifying risky IAM and cloud configuration patterns from sample JSON data.

The goal is to build a practical, explainable project that shows cloud security reasoning without requiring a live AWS or Azure account during the early stages.

## Current Scope

### Module 1: IAM Policy Analyzer

The first module analyzes sample IAM users, identity policies, and trust policies for common cloud security risks:

- Wildcard actions such as `Action: "*"`
- Wildcard resources such as `Resource: "*"`
- Administrator-style access
- Broad S3 permissions
- Missing MFA conditions on sensitive access
- Cross-account trust relationships
- Long-lived access keys in sample user metadata

The analyzer produces terminal findings and exports structured JSON evidence for reporting.

Current rule IDs:

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
- Missing default encryption
- Missing or suspended versioning

Current rule IDs:

| Rule | Risk Pattern |
| --- | --- |
| `STO-001` | S3 public access block is incomplete |
| `STO-002` | Bucket ACL grants public access |
| `STO-003` | Bucket policy allows public principal |
| `STO-004` | Bucket encryption is disabled |
| `STO-005` | Bucket versioning is not enabled |

### Module 4: Network Configuration Analyzer

The network analyzer checks sample security group configurations for risky network exposure:

- Sensitive ports open to `0.0.0.0/0` or `::/0`
- All inbound ports open to the internet
- Unrestricted outbound traffic to the internet

Current rule IDs:

| Rule | Risk Pattern |
| --- | --- |
| `NET-001` | Sensitive port is open to the internet |
| `NET-002` | All inbound ports are open to the internet |
| `NET-003` | Unrestricted outbound traffic is allowed |

## Planned Modules

The project is planned as a phased cloud security lab:

1. IAM policy analyzer
2. Risk report generator
3. Storage exposure analyzer
4. Network configuration analyzer
5. CloudTrail-style event detector

## Run the IAM Analyzer

From the project root:

```bash
python3 iam_analyzer/analyzer.py sample_data/iam/sample_iam_environment.json
```

Export findings as JSON:

```bash
python3 iam_analyzer/analyzer.py \
  sample_data/iam/sample_iam_environment.json \
  --output reports/generated/iam_findings.json
```

## Run the Storage Analyzer

```bash
python3 storage_analyzer/analyzer.py \
  sample_data/storage/sample_storage_environment.json
```

Export findings as JSON:

```bash
python3 storage_analyzer/analyzer.py \
  sample_data/storage/sample_storage_environment.json \
  --output reports/generated/storage_findings.json
```

## Run the Network Analyzer

```bash
python3 network_analyzer/analyzer.py \
  sample_data/network/sample_network_environment.json
```

Export findings as JSON:

```bash
python3 network_analyzer/analyzer.py \
  sample_data/network/sample_network_environment.json \
  --output reports/generated/network_findings.json
```

## Generate Risk Report

```bash
python3 report_generator/generate_report.py \
  --findings reports/generated/iam_findings.json \
  --findings reports/generated/storage_findings.json \
  --findings reports/generated/network_findings.json \
  --output reports/generated/cloud_security_report.md
```

A committed sample report is available at `reports/cloud_security_report_sample.md`.

## Run Tests

```bash
python3 -m unittest discover
```

## Project Structure

```text
cloud_security_misconfiguration_lab/
├── README.md
├── cloud_findings/
│   └── finding.py
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
├── sample_data/
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
└── .gitignore
```

## Safety Boundary

This project starts with offline sample data. Do not connect it to a real cloud account unless the account is owned by you or you have explicit permission to assess it.
