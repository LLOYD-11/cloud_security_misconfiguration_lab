# IAM Policy Analyzer

This module analyzes offline IAM-style JSON data and reports risky identity and permission patterns using the shared finding schema.

It is intentionally offline-first. The module does not call AWS APIs or require cloud credentials. The unified CLI can normalize previously exported AWS IAM authorization details and credential reports before running this analyzer.

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
| `IAM-005` | Medium | Allows a sensitive user action without an MFA policy condition |
| `IAM-006` | Medium | User metadata shows MFA is disabled |
| `IAM-007` | Medium | Access key is older than 90 days |
| `IAM-008` | High | Role trust policy allows an external AWS or federated principal |

Each IAM finding includes references to the relevant MITRE ATT&CK or AWS IAM best-practice documentation where applicable.

The analyzer evaluates AWS and federated principals individually, so a mixed same-account and external principal list is not treated as entirely trusted. AWS service principals such as `lambda.amazonaws.com` are not classified as cross-account principals.

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

Native AWS exports are supported through the unified CLI:

```bash
python3 -m cloud_security_lab analyze iam \
  sample_data/aws/iam/account_authorization_details.json \
  --input-format aws \
  --credential-report sample_data/aws/iam/credential_report.csv \
  --as-of 2026-06-30 \
  --output reports/generated/iam_findings.json
```

See [`docs/native-aws-inputs.md`](../docs/native-aws-inputs.md) for collection and normalization details. The standalone compatibility script continues to accept the simplified IAM environment only.

## Test

```bash
python3 -m unittest iam_analyzer.test_analyzer
```
