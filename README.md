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

## Generate Risk Report

```bash
python3 report_generator/generate_report.py \
  --findings reports/generated/iam_findings.json \
  --output reports/generated/cloud_security_report.md
```

A committed sample report is available at `reports/cloud_security_report_sample.md`.

## Run Tests

```bash
python3 -m unittest iam_analyzer.test_analyzer report_generator.test_generate_report
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
├── report_generator/
│   ├── generate_report.py
│   ├── README.md
│   └── test_generate_report.py
├── reports/
│   └── cloud_security_report_sample.md
├── sample_data/
│   └── iam/
│       └── sample_iam_environment.json
└── .gitignore
```

## Safety Boundary

This project starts with offline sample data. Do not connect it to a real cloud account unless the account is owned by you or you have explicit permission to assess it.
