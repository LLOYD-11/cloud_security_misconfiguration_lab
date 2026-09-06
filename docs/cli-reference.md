# Command-Line Reference

This reference contains the detailed commands moved out of the reviewer-first
README. Run commands from the repository root.

## Installation

The runtime requires Python 3.10 or later and has no third-party dependencies.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/cloud-security-lab --help
```

The installed `cloud-security-lab` command and
`python3 -m cloud_security_lab` expose the same `analyze`, `report`, `catalog`,
and `demo` subcommands.

## Deterministic Demo

```bash
python3 -m cloud_security_lab demo --report-date 2026-06-30
```

The explicit date makes sample output reproducible. Generated artifacts are
written under `reports/generated/`; the final report must match the committed
[`cloud_security_report_sample.md`](../reports/cloud_security_report_sample.md)
byte-for-byte.

## Analyze Simplified Evidence

```bash
python3 -m cloud_security_lab analyze iam \
  sample_data/iam/sample_iam_environment.json \
  --output reports/generated/iam_findings.json \
  --summary-output reports/generated/iam_analysis_summary.json
```

Every simplified JSON file crosses the dependency-free
[runtime validation boundary](simplified-input-validation.md). Stable
JSON-style error paths identify the first invalid consumed field.

## Analyze Native AWS-Shaped Evidence

The lab reads exported files; it does not authenticate to AWS. Collection
commands and completeness requirements are documented in
[Native AWS inputs](native-aws-inputs.md).

### IAM

```bash
python3 -m cloud_security_lab analyze iam \
  sample_data/aws/iam/account_authorization_details.json \
  --input-format aws \
  --credential-report sample_data/aws/iam/credential_report.csv \
  --as-of 2026-06-30 \
  --observed-at 2026-06-30T00:00:00Z \
  --normalized-output reports/generated/normalized_iam_environment.json \
  --output reports/generated/iam_findings.json \
  --summary-output reports/generated/iam_analysis_summary.json
```

`--as-of` controls credential-age calculations. Supply it explicitly for a
reproducible result.

### S3

```bash
python3 -m cloud_security_lab analyze storage \
  sample_data/aws/s3/s3_security_evidence_bundle.json \
  --input-format aws \
  --normalized-output reports/generated/normalized_storage_environment.json \
  --output reports/generated/storage_findings.json \
  --summary-output reports/generated/storage_analysis_summary.json
```

### EC2 Security Groups

```bash
python3 -m cloud_security_lab analyze network \
  sample_data/aws/ec2/describe_security_groups.json \
  --input-format aws \
  --reachability-context sample_data/aws/ec2/network_reachability_context.json \
  --region ap-southeast-2 \
  --normalized-output reports/generated/normalized_network_environment.json \
  --output reports/generated/network_findings.json \
  --summary-output reports/generated/network_analysis_summary.json
```

`--reachability-context` is optional assessor-supplied evidence. The lab does
not independently reproduce an AWS network-path analysis.

### CloudTrail

```bash
python3 -m cloud_security_lab analyze cloudtrail \
  sample_data/aws/cloudtrail/111122223333_CloudTrail_20260630T0200Z_part1.json \
  sample_data/aws/cloudtrail/111122223333_CloudTrail_20260630T0300Z_part2.json.gz \
  --input-format aws \
  --normalized-output reports/generated/normalized_cloudtrail_environment.json \
  --output reports/generated/cloudtrail_findings.json \
  --incidents-output reports/generated/cloudtrail_incidents.json \
  --summary-output reports/generated/cloudtrail_analysis_summary.json
```

All external evidence and report artifacts cross measured
[input resource limits](input-resource-limits.md) for encoded and decompressed
bytes, JSON nodes and depth, resource counts, and file counts.

## Inspect The Rule Catalog

```bash
python3 -m cloud_security_lab catalog
python3 -m cloud_security_lab catalog --module storage --format json
```

The catalog contains allowed severities, confidence bases, and qualified
`direct` or `related` mappings. The committed
[catalog reference](rule-catalog.md) is generated from the same versioned JSON
used by analyzers and reporting.

## Build A Combined Report

```bash
python3 -m cloud_security_lab report \
  --findings reports/generated/iam_findings.json \
  --findings reports/generated/storage_findings.json \
  --findings reports/generated/network_findings.json \
  --findings reports/generated/cloudtrail_findings.json \
  --incidents reports/generated/cloudtrail_incidents.json \
  --analysis-summary reports/generated/iam_analysis_summary.json \
  --analysis-summary reports/generated/storage_analysis_summary.json \
  --analysis-summary reports/generated/network_analysis_summary.json \
  --analysis-summary reports/generated/cloudtrail_analysis_summary.json \
  --report-date 2026-06-30 \
  --remediation-output reports/generated/remediation_plan.json \
  --timeline-output reports/generated/attack_timeline.json \
  --output reports/generated/cloud_security_report.md
```

Omit `--report-date` to use the current local date. Reports validate artifact
versions and relationships before applying the documented
[Markdown integrity boundary](report-integrity.md).

## Compatibility Entrypoints

The original module scripts remain supported:

```bash
python3 iam_analyzer/analyzer.py sample_data/iam/sample_iam_environment.json
python3 storage_analyzer/analyzer.py sample_data/storage/sample_storage_environment.json
python3 network_analyzer/analyzer.py sample_data/network/sample_network_environment.json
python3 cloudtrail_detector/detector.py sample_data/cloudtrail/sample_cloudtrail_events.json
```

## Development Verification

Install the SHA-256-locked development environment before running the complete
gate:

```bash
.venv/bin/python -m pip install --require-hashes -r requirements-dev.lock
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
.venv/bin/python -m pip check
```

The authoritative command set is maintained in
[Engineering checks](engineering.md). It covers lint, strict production type
checking, Markdown and links, the frozen evaluation, unit and regression tests,
statement and branch coverage, deterministic benchmarks, packaging, and
installed-wheel execution.

## Safety Boundary

- Analyze only evidence that you own or are authorized to assess.
- Do not commit credentials, raw personal cloud exports, or generated reports
  containing account identifiers.
- Treat findings as review leads, not proof that an account is secure or
  compromised.
- Review [Known limitations](known-limitations.md) before interpreting output.
