# Risk Report Generator

This module generates a Markdown risk report from one or more shared finding JSON files.

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

## Generate IAM Findings First

```bash
python3 iam_analyzer/analyzer.py \
  sample_data/iam/sample_iam_environment.json \
  --output reports/generated/iam_findings.json
```

## Generate Report

```bash
python3 report_generator/generate_report.py \
  --findings reports/generated/iam_findings.json \
  --output reports/generated/cloud_security_report.md
```

The `--findings` option can be repeated as new modules are added:

```bash
python3 report_generator/generate_report.py \
  --findings reports/generated/iam_findings.json \
  --findings reports/generated/storage_findings.json \
  --findings reports/generated/network_findings.json \
  --findings reports/generated/cloudtrail_findings.json \
  --output reports/generated/cloud_security_report.md
```

## Test

```bash
python3 -m unittest report_generator.test_generate_report
```
