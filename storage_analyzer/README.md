# Storage Exposure Analyzer

This module analyzes offline S3-style bucket configuration data for common storage exposure risks.

It does not call AWS APIs or require cloud credentials. The standalone analyzer consumes the simplified storage contract, while the unified CLI can normalize a versioned bundle of previously exported native AWS S3 responses before running the same rules.

## Detection Rules

| Rule | Severity | Description |
| --- | --- | --- |
| `STO-001` | High | S3 public access block is incomplete |
| `STO-002` | Critical | Bucket ACL grants public access |
| `STO-003` | Critical | Bucket policy allows an effectively public principal |
| `STO-004` | Low | Bucket lacks an explicit encryption configuration beyond the S3 SSE-S3 baseline |
| `STO-005` | Medium | Bucket versioning is not enabled |
| `STO-006` | Medium | Bucket ACLs remain enabled by Object Ownership |

Each finding uses the shared schema and includes references to AWS S3 documentation or MITRE ATT&CK where applicable.

Public ACL and bucket-policy findings respect `BucketOwnerEnforced`, effective `IgnorePublicAcls`, and effective `RestrictPublicBuckets` controls. Persisted public configuration is not labeled active exposure when S3 blocks that access path.

For wildcard principals and broad `NotPrincipal` allows, the analyzer follows the documented S3 Block Public Access model: a statement is considered non-public only when a supported positive condition operator uses fixed values for an AWS-recognized organization, account, source ARN, VPC, VPC endpoint, data access point, or source network. Wildcards, policy variables, negative operators, `IfExists`, malformed values, IPv4 ranges broader than `/8`, and IPv6 ranges broader than `/32` do not suppress a public-policy finding. RFC 1918 source networks are treated as non-public. A `ForAllValues` guard must also include `Null: false` for the same key so a missing request-context key cannot satisfy the condition.

Non-public classification is not a trust decision. Fixed external accounts, organizations, public CIDRs, and service integrations still require authorization review.

The optional `object_ownership` field preserves compatibility with earlier simplified inputs. Native S3 normalization always supplies it from `GetBucketOwnershipControls`.

## Run

```bash
python3 storage_analyzer/analyzer.py \
  sample_data/storage/sample_storage_environment.json
```

Export JSON:

```bash
python3 storage_analyzer/analyzer.py \
  sample_data/storage/sample_storage_environment.json \
  --output reports/generated/storage_findings.json
```

The exported JSON can be passed directly to `report_generator/generate_report.py`.

Analyze the bundled native AWS evidence:

```bash
python3 -m cloud_security_lab analyze storage \
  sample_data/aws/s3/s3_security_evidence_bundle.json \
  --input-format aws \
  --normalized-output reports/generated/normalized_storage_environment.json \
  --output reports/generated/storage_findings.json
```

See [`docs/native-aws-inputs.md`](../docs/native-aws-inputs.md) for the evidence-bundle contract, expected AWS errors, and normalization behavior.

## Test

```bash
python3 -m unittest storage_analyzer.test_analyzer
```
