# Native AWS Inputs

All four analyzers can consume exported AWS API evidence without requiring the lab to hold cloud credentials or call a live account.

## IAM Evidence

### Collect IAM Evidence

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
- [Permissions boundaries for IAM entities](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [GetCredentialReport API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetCredentialReport.html)

### Analyze IAM Evidence

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

### IAM Normalization Behavior

The adapter:

- Resolves the default document for attached managed policies.
- Preserves direct identity policies separately from IAM group policies and records group membership.
- Converts role assume-role documents into the analyzer trust-policy model.
- Resolves user and role permissions-boundary documents when they are present in the authorization snapshot.
- Derives console-password, MFA, access-key age, and access-key last-used posture from the credential report.
- Preserves root password, MFA, and active-key posture for dedicated root credential checks.
- Infers and cross-checks the AWS account ID from IAM ARNs.
- Emits warnings when referenced group, managed-policy, or permissions-boundary evidence is absent.

Missing user credential rows, conflicting account IDs, malformed policies, invalid credential fields, and truncated authorization details stop analysis. A missing root row is accepted for compatibility with pre-normalized or reduced evidence, but native AWS credential reports normally include it. The normalizer does not silently replace missing password, MFA, or access-key evidence with a default value.

Credential reports do not expose access-key IDs, so normalized keys use stable slot labels such as `credential-report:key-1`. AWS credential reports cover the first two IAM access keys and do not include service-specific credentials; see the AWS credential report documentation for that evidence boundary. Stale credential checks use the explicit `--as-of` date and a 90-day threshold.

## S3 Evidence

S3 security state is distributed across account-level and per-bucket operations. The storage normalizer therefore consumes a versioned evidence bundle that preserves each native response under its AWS operation name.

The bundle contract is [`aws-s3-evidence-bundle-v1.0.schema.json`](../schemas/aws-s3-evidence-bundle-v1.0.schema.json). Its main fields are:

| Field | AWS evidence |
| --- | --- |
| `ListBuckets` | Complete `s3api list-buckets` response |
| `AccountPublicAccessBlock` | `s3control get-public-access-block` response or expected not-found error |
| `BucketEvidence[].GetPublicAccessBlock` | Bucket-level Block Public Access response or expected not-found error |
| `BucketEvidence[].GetBucketOwnershipControls` | S3 Object Ownership response or expected not-found error |
| `BucketEvidence[].GetBucketAcl` | Bucket ACL response |
| `BucketEvidence[].GetBucketPolicy` | Bucket policy response or expected not-found error |
| `BucketEvidence[].GetBucketEncryption` | Default encryption response |
| `BucketEvidence[].GetBucketVersioning` | Versioning response, including `{}` when never enabled |

Representative collection commands are:

```bash
aws s3api list-buckets --output json
aws s3control get-public-access-block --account-id 111122223333 --output json
aws s3api get-public-access-block --bucket BUCKET_NAME --output json
aws s3api get-bucket-ownership-controls --bucket BUCKET_NAME --output json
aws s3api get-bucket-acl --bucket BUCKET_NAME --output json
aws s3api get-bucket-policy --bucket BUCKET_NAME --output json
aws s3api get-bucket-encryption --bucket BUCKET_NAME --output json
aws s3api get-bucket-versioning --bucket BUCKET_NAME --output json
```

Run collection only against accounts you own or are authorized to assess. Store successful JSON bodies unchanged inside the bundle. When an optional configuration is absent, store an error envelope such as:

```json
{
  "Error": {
    "Code": "NoSuchBucketPolicy"
  }
}
```

Only `NoSuchPublicAccessBlockConfiguration`, `NoSuchBucketPolicy`, and `OwnershipControlsNotFoundError` are interpreted as absent optional configuration. Missing ownership controls are represented as legacy ACL-enabled `ObjectWriter` behavior with a visible warning. `AccessDenied`, malformed responses, incomplete bucket coverage, and any paginated or prefix-filtered `ListBuckets` response stop analysis instead of being converted into insecure defaults.

### Analyze S3 Evidence

```bash
python3 -m cloud_security_lab analyze storage \
  sample_data/aws/s3/s3_security_evidence_bundle.json \
  --input-format aws \
  --normalized-output reports/generated/normalized_storage_environment.json \
  --output reports/generated/storage_findings.json
```

### S3 Normalization Behavior

The adapter:

- Requires one evidence entry for every bucket returned by a complete, unfiltered `ListBuckets` response, with no unlisted extras.
- Combines account-level and bucket-level Block Public Access controls using S3's most-restrictive behavior.
- Preserves `BucketOwnerEnforced`, `BucketOwnerPreferred`, or `ObjectWriter` from Object Ownership controls and makes ACL effectiveness explicit.
- Converts AWS ACL grantee structures into stable analyzer identifiers while retaining public group URIs.
- Parses the JSON string returned by `GetBucketPolicy` and preserves principal, action, resource, and condition semantics, including `NotPrincipal`, `NotAction`, and `NotResource`.
- Reads SSE-S3, SSE-KMS, and DSSE-KMS default encryption responses without claiming that baseline SSE-S3 is absent. A 2026 `BlockedEncryptionTypes`-only rule is normalized to the S3 SSE-S3 baseline with a visible warning.
- Converts an empty `GetBucketVersioning` response to the analyzer's `Disabled` state.

Current S3 references:

- [ListBuckets API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html)
- [GetPublicAccessBlock API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html)
- [GetBucketOwnershipControls API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketOwnershipControls.html)
- [S3 Object Ownership](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html)
- [GetBucketAcl CLI response](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-acl.html)
- [GetBucketPolicy API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html)
- [GetBucketEncryption CLI response](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-encryption.html)
- [ServerSideEncryptionRule API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ServerSideEncryptionRule.html)
- [Blocking or unblocking SSE-C](https://docs.aws.amazon.com/AmazonS3/latest/userguide/blocking-unblocking-s3-c-encryption-gpb.html)
- [GetBucketVersioning API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html)

## EC2 Security Group Evidence

### Collect EC2 Evidence

Run the following command only against an account that you own or are authorized to assess:

```bash
aws ec2 describe-security-groups \
  --output json > describe-security-groups.json
```

Do not add `--filters`, `--group-ids`, `--max-items`, or `--no-paginate`. The input contract represents one complete, unfiltered account snapshot. A non-null `NextToken` is rejected because omitted pages would create false negatives. The direct-response contract is [`aws-ec2-describe-security-groups-v1.0.schema.json`](../schemas/aws-ec2-describe-security-groups-v1.0.schema.json).

### Analyze EC2 Evidence

```bash
python3 -m cloud_security_lab analyze network \
  describe-security-groups.json \
  --input-format aws \
  --reachability-context network-reachability-context.json \
  --normalized-output reports/generated/normalized_network_environment.json \
  --output reports/generated/network_findings.json
```

The bundled native-shape sample can be analyzed with the same command:

```bash
python3 -m cloud_security_lab analyze network \
  sample_data/aws/ec2/describe_security_groups.json \
  --input-format aws \
  --reachability-context sample_data/aws/ec2/network_reachability_context.json
```

`--reachability-context` is optional. Without it, the analyzer reports security-group permission risk with `reachability_status: not_assessed`.

### Optional Reachability Evidence

`DescribeSecurityGroups` cannot prove end-to-end connectivity. Internet access can also depend on public addresses, internet gateways, routes, network interfaces, load balancers, network ACLs, and other controls. AWS Reachability Analyzer models these path components without sending packets; Network Access Analyzer can identify network paths matching a scope.

The lab accepts a separate, versioned assessor-supplied conclusion through [`network-reachability-context-v1.0.schema.json`](../schemas/network-reachability-context-v1.0.schema.json). Each entry must identify:

- The matching security-group ID.
- An assessment method and RFC 3339 observation timestamp.
- Independent ingress and egress status: `reachable`, `not_reachable`, or `inconclusive`.
- A direction-specific scope describing the covered attachments, address families, protocols, ports, and paths.
- At least one evidence statement per direction.
- Optional related AWS resource IDs.

The adapter rejects duplicate or unknown security-group IDs, unsupported methods and statuses, timestamps without offsets, empty scope or evidence, and extra fields. Partial context is accepted with a warning; uncovered groups remain `not_assessed`. When an auxiliary file is supplied, it replaces the environment's complete embedded context set so stale unmatched assessments cannot survive silently.

This is an evidence-attestation contract, not a raw AWS export parser. A status applies to every finding covered by the stated direction scope, so use `inconclusive` unless the assessment covers every relevant attachment, address family, protocol, port, and intermediary path in that scope. AWS Reachability Analyzer and Network Access Analyzer are currently IPv4-only; they must not be cited as evidence for IPv6 conclusions. The lab does not query an account, reproduce the path calculation, or verify that the stated resource IDs and conclusions match live AWS configuration. Keep the source AWS analysis or approved topology review with the assessment record, and refresh it after network changes.

### EC2 Normalization Behavior

The adapter:

- Requires a non-empty, complete response with unique security-group IDs from one owner account.
- Cross-checks each security-group ARN against its owner account and group ID.
- Validates VPC, security-group, prefix-list, and VPC peering identifiers.
- Normalizes named and numeric IP protocols, validates TCP/UDP port ranges and ICMP type/code values, and canonicalizes IPv4 and IPv6 CIDRs.
- Flattens each IPv4 range, IPv6 range, prefix-list entry, and referenced security group into one normalized rule while preserving descriptions and peer context.
- Preserves group names, descriptions, owner IDs, VPC IDs, ARNs, and tags for traceability.
- Emits visible warnings when prefix-list or security-group targets are present.
- Optionally attaches validated, point-in-time reachability conclusions before detection and normalized evidence export.

The analyzer evaluates public exposure only for explicit CIDR targets. It does not retrieve prefix-list members or expand referenced security groups. It does not independently prove workload reachability; optional context can supply a separately obtained conclusion and is reported with its method, timestamp, and evidence. A filtered AWS response has no self-describing filter marker, so completeness also depends on using the documented unfiltered collection command.

Current EC2 references:

- [DescribeSecurityGroups CLI](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html)
- [IpPermission API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html)
- [Security group rule components](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
- [How Reachability Analyzer works](https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html)
- [How Network Access Analyzer works](https://docs.aws.amazon.com/vpc/latest/network-access-analyzer/how-network-access-analyzer-works.html)
- [Internet gateway requirements](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html)

## CloudTrail Log Evidence

CloudTrail trail log objects are JSON text delivered to S3 in gzip archives. Each supported file contains a top-level `Records` list. Download logs only from a trail and S3 bucket that you own or are authorized to assess. A representative collection command is:

```bash
aws s3 cp s3://authorized-cloudtrail-bucket/AWSLogs/111122223333/CloudTrail/ \
  ./cloudtrail-logs/ \
  --recursive \
  --exclude "*" \
  --include "*.json.gz"
```

The supported direct-log contract is [`aws-cloudtrail-records-v1.0.schema.json`](../schemas/aws-cloudtrail-records-v1.0.schema.json). CloudTrail Insight, aggregated-event, and digest files use different structures and are not accepted by this adapter.

### Analyze CloudTrail Evidence

Pass one or more downloaded `.json` or `.json.gz` files as positional inputs:

```bash
python3 -m cloud_security_lab analyze cloudtrail \
  cloudtrail-logs/first.json.gz \
  cloudtrail-logs/second.json.gz \
  --input-format aws \
  --normalized-output reports/generated/normalized_cloudtrail_environment.json \
  --output reports/generated/cloudtrail_findings.json
```

The bundled sample demonstrates one uncompressed file and one gzip file:

```bash
python3 -m cloud_security_lab analyze cloudtrail \
  sample_data/aws/cloudtrail/111122223333_CloudTrail_20260630T0200Z_part1.json \
  sample_data/aws/cloudtrail/111122223333_CloudTrail_20260630T0300Z_part2.json.gz \
  --input-format aws
```

### CloudTrail Normalization Behavior

The adapter:

- Reads multiple UTF-8 JSON or gzip-compressed JSON files and requires a non-empty `Records` list in each.
- Accepts CloudTrail event format major version 1 and preserves compatible minor-version fields.
- Validates event GUIDs, UTC timestamps, service, action, Region, source, identity, request/response shapes, and account identifiers.
- Uses `recipientAccountId` as the evidence-account boundary, falling back to `userIdentity.accountId` or its ARN for older records.
- Requires all unique records in one analysis to resolve to the same recipient account.
- Removes identical duplicate records by `eventID` with a warning and rejects conflicting records that reuse an ID.
- Writes the merged environment through `--normalized-output` so the detector input remains inspectable.

The adapter loads evidence into memory and does not verify CloudTrail digest signatures. The detector still applies a selected rule catalog rather than reconstructing every request or correlating a full incident.

Current CloudTrail references:

- [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [Getting and viewing CloudTrail log files](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html)
- [CloudTrail log file examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html)
- [Downloading CloudTrail log files](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-read-log-files.html)
