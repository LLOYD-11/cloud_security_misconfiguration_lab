# Risk Report Generator

This module generates a Markdown risk report from one or more shared finding JSON files.

Finding inputs must use the versioned object written by the analyzers. The loader rejects unsupported schema versions, mismatched `finding_count` values, missing required fields, and unknown severities instead of silently omitting malformed findings.

Every analyzer should output the same finding schema:

- `rule_id`
- `severity`
- `module`
- `category`
- `resource_type`
- `resource_id`
- `title`
- `evidence`
- `impact`
- `remediation`
- `references`
- `metadata`

## Generate Module Findings First

```bash
python3 iam_analyzer/analyzer.py \
  sample_data/iam/sample_iam_environment.json \
  --output reports/generated/iam_findings.json
python3 storage_analyzer/analyzer.py \
  sample_data/storage/sample_storage_environment.json \
  --output reports/generated/storage_findings.json
python3 network_analyzer/analyzer.py \
  sample_data/network/sample_network_environment.json \
  --output reports/generated/network_findings.json
python3 cloudtrail_detector/detector.py \
  sample_data/cloudtrail/sample_cloudtrail_events.json \
  --output reports/generated/cloudtrail_findings.json
```

## Generate Report

```bash
python3 report_generator/generate_report.py \
  --findings reports/generated/iam_findings.json \
  --findings reports/generated/storage_findings.json \
  --findings reports/generated/network_findings.json \
  --findings reports/generated/cloudtrail_findings.json \
  --report-date 2026-06-30 \
  --output reports/generated/cloud_security_report.md
```

The `--findings` option can be repeated as new modules are added. Use `--report-date YYYY-MM-DD` for deterministic output, or omit it to use the current local date.

## Test

```bash
python3 -m unittest report_generator.test_generate_report
```
