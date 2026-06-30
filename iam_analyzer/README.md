# IAM Policy Analyzer

This module analyzes offline IAM-style JSON data and reports risky identity and permission patterns using the shared finding schema.

It is intentionally offline-first. The sample data is shaped like cloud IAM data, but the module does not call AWS APIs or require cloud credentials.

## Input Model

The analyzer expects a JSON object with:

- `account_id`
- `users`
- `roles`

Each user or role can include:

- `name`
- `mfa_enabled`
- `access_keys`
- `attached_policies`
- `trust_policy` for roles

Policies use simplified IAM-style statements with `effect`, `action`, `resource`, and optional `condition` fields. Uppercase AWS-style keys such as `Effect`, `Action`, `Resource`, and `Condition` are also supported.

## Detection Rules

| Rule | Severity | Description |
| --- | --- | --- |
| `IAM-001` | Critical | Allows `Action "*"` on `Resource "*"` |
| `IAM-002` | High | Allows wildcard action |
| `IAM-003` | Medium | Uses wildcard resource |
| `IAM-004` | High | Allows broad S3 write access |
| `IAM-005` | Medium | Allows sensitive action without an MFA condition |
| `IAM-006` | Medium | User metadata shows MFA is disabled |
| `IAM-007` | Medium | Access key is older than 90 days |
| `IAM-008` | High | Role trust policy allows an external account |

Each IAM finding includes references to the relevant MITRE ATT&CK or AWS IAM best-practice documentation where applicable.

## Run

```bash
python3 iam_analyzer/analyzer.py sample_data/iam/sample_iam_environment.json
```

Export JSON:

```bash
python3 iam_analyzer/analyzer.py \
  sample_data/iam/sample_iam_environment.json \
  --output reports/generated/iam_findings.json
```

The exported JSON can be passed directly to `report_generator/generate_report.py`.

## Test

```bash
python3 -m unittest iam_analyzer.test_analyzer
```
