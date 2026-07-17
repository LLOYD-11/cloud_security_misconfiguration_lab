# IAM Policy Analyzer

This module analyzes offline IAM-style JSON data and reports risky identity and permission patterns using the shared finding schema.

It is intentionally offline-first. The module does not call AWS APIs or require cloud credentials. The unified CLI can normalize previously exported AWS IAM authorization details and credential reports before running this analyzer.

## Input Model

The analyzer expects a JSON object with:

- `account_id`
- `users`
- optional `groups`
- `roles`
- optional `root_account` credential posture

Each user or role can include:

- `name`
- console-password and MFA status for users
- `access_keys`
- `attached_policies`
- `permissions_boundary`
- `trust_policy` for roles

Groups contain their own attached policies and a member list, so one risky group statement produces one finding with member context rather than duplicate findings for every user.

Policies use simplified IAM-style statements with `effect`, `action` or `not_action`, `resource` or `not_resource`, and optional `condition` fields. Uppercase AWS-style keys such as `Effect`, `Action`, `NotAction`, `Resource`, `NotResource`, and `Condition` are also supported.

## Detection Rules

| Rule | Severity | Description |
| --- | --- | --- |
| `IAM-001` | Critical | Allows `Action "*"` on `Resource "*"` |
| `IAM-002` | Medium/High | Allows full, service, or partial wildcard action |
| `IAM-003` | Medium | Uses unscoped `Resource "*"` |
| `IAM-004` | High | Allows broad S3 write access |
| `IAM-005` | Medium | User or group policy allows a sensitive action without an MFA condition |
| `IAM-006` | Medium | Console-enabled user does not have MFA |
| `IAM-007` | Medium | Access key is older than 90 days |
| `IAM-008` | Medium-Critical | Role trust allows a public or external principal |
| `IAM-009` | Medium/High | Allow statement uses a broad `NotAction` complement |
| `IAM-010` | Medium/High | Allow statement uses a broad `NotResource` complement |
| `IAM-011` | Medium | Active access key is unused for more than 90 days |
| `IAM-012` | Medium | Active console password is unused for more than 90 days |
| `IAM-013` | Critical | Root account has an active access key |
| `IAM-014` | Critical | Root account has a password but no MFA |
| `IAM-015` | Medium | Permissions boundary allows `Action "*"` on `Resource "*"` |

Each IAM finding includes references to the relevant MITRE ATT&CK or AWS IAM best-practice documentation where applicable.

The analyzer evaluates AWS and federated principals individually, so a mixed same-account and external principal list is not treated as entirely trusted. AWS service principals such as `lambda.amazonaws.com` are not classified as cross-account principals. A public trust is critical by default, while a well-formed equality condition using `sts:ExternalId`, `aws:PrincipalOrgID`, or `aws:PrincipalArn` lowers the rule severity without hiding the trust relationship.

Permissions boundaries are treated as maximum-permission context, not as grants. Boundary ARNs and document availability are attached to identity-policy findings, and only an explicitly unrestricted boundary receives its own finding.

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
