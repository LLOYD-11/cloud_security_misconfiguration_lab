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

The analyzer produces terminal findings and can export structured JSON evidence for later reporting.

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

## Planned Modules

The project structure leaves room for later modules, but the first milestone is intentionally narrow:

1. IAM policy analyzer
2. Risk report generator
3. Storage exposure analyzer
4. Network configuration analyzer
5. CloudTrail-style event detector

Module 1 and the risk report generator are the core target. The other modules should be added only if they improve the project without making the scope noisy.

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

## Run Tests

```bash
python3 -m unittest iam_analyzer.test_analyzer
```

## Project Structure

```text
cloud_security_misconfiguration_lab/
├── README.md
├── iam_analyzer/
│   ├── analyzer.py
│   ├── README.md
│   └── test_analyzer.py
├── sample_data/
│   └── iam/
│       └── sample_iam_environment.json
└── reports/
```

## Safety Boundary

This project starts with offline sample data. Do not connect it to a real cloud account unless the account is owned by you or you have explicit permission to assess it.
