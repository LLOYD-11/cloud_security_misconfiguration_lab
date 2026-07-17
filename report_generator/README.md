# Risk Report Generator

This module generates a Markdown risk report from one or more shared finding JSON files, optional correlated incident files, and optional analysis-summary files. It also derives an explainable remediation queue across findings and incidents and a chronological view of eligible CloudTrail evidence.

Finding inputs must use the versioned object written by the analyzers. The loader rejects unsupported schema versions, mismatched `finding_count` values, missing required fields, and unknown severities instead of silently omitting malformed findings. Known built-in rules are also checked against the versioned catalog for the correct module and allowed severity. Custom rule IDs remain supported and are labeled not cataloged.

Analysis summaries add evaluated and discovered resources, skipped evidence, normalization warnings, input format, and coverage status. The report rejects a summary whose declared finding or incident counts do not match the supplied result files. If any summary is supplied, every module represented by the supplied findings or incidents must have one.

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
  --output reports/generated/cloudtrail_findings.json \
  --incidents-output reports/generated/cloudtrail_incidents.json
```

## Generate Report

```bash
python3 report_generator/generate_report.py \
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

The `--findings`, `--incidents`, and `--analysis-summary` options can be repeated. Incident sections preserve the linked rule IDs, event counts, resources, severity, confidence, and recommended triage actions. Coverage sections distinguish complete, partial, and empty runs without treating zero findings as proof of safety. Triggered-rule context summarizes evidence-to-rule confidence and `direct` or `related` control mappings without presenting them as proof of malicious intent or full framework certification.

The remediation section uses published P0-P3 rules, keeps incident response separate from configuration hardening, and groups only findings with the same rule, severity, title, and action. `--remediation-output` writes the same queue under the versioned [`remediation-plan-v1.0`](../schemas/remediation-plan-v1.0.schema.json) contract. See [Remediation prioritization](../docs/remediation-prioritization.md) for the complete algorithm and interpretation boundary.

The attack timeline orders CloudTrail finding evidence by UTC time and retains
multi-event windows such as repeated API failures. It records findings that
cannot be placed chronologically, uses an exact rule-resource-event join for
incident context, and does not label observed activity as proven malicious
behavior. `--timeline-output` writes the versioned
[`attack-timeline-v1.0`](../schemas/attack-timeline-v1.0.schema.json) artifact.
See [Attack timeline](../docs/attack-timeline.md) for evidence and interpretation
rules.

Use `--report-date YYYY-MM-DD` for deterministic output, or omit it to use the current local date.

## Test

```bash
python3 -m unittest report_generator.test_generate_report
```
