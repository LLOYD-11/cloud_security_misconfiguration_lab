# Native AWS Inputs

The IAM analyzer can consume exports produced by AWS IAM without requiring the lab to hold cloud credentials or call a live account.

## Collect IAM Evidence

Run these commands only against an account that you own or are authorized to assess:

```bash
aws iam get-account-authorization-details \
  --output json > account-authorization-details.json

aws iam generate-credential-report

aws iam get-credential-report \
  --output json > credential-report.json
```

`get-account-authorization-details` returns users, groups, roles, managed policies, and their relationships. The normalizer rejects a response where `IsTruncated` is `true`; collect all pages before analysis so omitted identities do not create false negatives.

The credential report may be supplied either as the JSON response above, whose `Content` field contains Base64-encoded CSV, or as the decoded CSV file itself. AWS policy documents may be JSON objects, JSON strings, or RFC 3986 URL-encoded JSON.

AWS references:

- [GetAccountAuthorizationDetails API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
- [IAM credential report format](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html)
- [GetCredentialReport API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetCredentialReport.html)

## Analyze Native Evidence

```bash
python3 -m cloud_security_lab analyze iam \
  account-authorization-details.json \
  --input-format aws \
  --credential-report credential-report.json \
  --as-of 2026-06-30 \
  --normalized-output reports/generated/normalized_iam_environment.json \
  --output reports/generated/iam_findings.json
```

`--as-of` controls credential-age calculations and defaults to the current local date. Supply it explicitly for reproducible results.

The bundled native-shape sample uses a readable decoded credential report:

```bash
python3 -m cloud_security_lab analyze iam \
  sample_data/aws/iam/account_authorization_details.json \
  --input-format aws \
  --credential-report sample_data/aws/iam/credential_report.csv \
  --as-of 2026-06-30
```

## Normalization Behavior

The adapter:

- Resolves the default document for attached managed policies.
- Combines direct user policies with policies inherited from IAM groups.
- Converts role assume-role documents into the analyzer trust-policy model.
- Derives MFA status and active access-key age from the credential report.
- Infers and cross-checks the AWS account ID from IAM ARNs.
- Emits warnings when referenced group or managed-policy evidence is absent.

Missing credential rows, conflicting account IDs, malformed policies, invalid credential fields, and truncated authorization details stop analysis. The normalizer does not silently replace missing MFA or access-key evidence with a default value.

Credential reports do not expose access-key IDs, so normalized keys use stable slot labels such as `credential-report:key-1`. AWS credential reports cover the first two IAM access keys and do not include service-specific credentials; see the AWS credential report documentation for that evidence boundary.
