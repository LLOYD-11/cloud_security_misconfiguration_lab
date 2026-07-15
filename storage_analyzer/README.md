# Storage Exposure Analyzer

This module analyzes offline S3-style bucket configuration data for common storage exposure risks.

It does not call AWS APIs or require cloud credentials. The standalone analyzer consumes the simplified storage contract, while the unified CLI can normalize a versioned bundle of previously exported native AWS S3 responses before running the same rules.

## Detection Rules

| Rule | Severity | Description |
| --- | --- | --- |
| `STO-001` | High | S3 public access block is incomplete |
| `STO-002` | Critical | Bucket ACL grants public access |
| `STO-003` | Critical | Bucket policy allows a public principal |
| `STO-004` | Low | Bucket lacks an explicit encryption configuration beyond the S3 SSE-S3 baseline |
| `STO-005` | Medium | Bucket versioning is not enabled |

Each finding uses the shared schema and includes references to AWS S3 documentation or MITRE ATT&CK where applicable.

Public ACL and bucket-policy findings respect effective `IgnorePublicAcls` and `RestrictPublicBuckets` controls. Persisted public configuration is not labeled active exposure when S3 blocks that access path.

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
