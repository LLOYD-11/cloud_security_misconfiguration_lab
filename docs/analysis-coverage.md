# Analysis Coverage

Findings describe detected risk. They do not describe how much evidence reached an analyzer. The versioned analysis-summary contract keeps those two questions separate.

## Output

Run any unified analyzer with `--summary-output`:

```bash
python3 -m cloud_security_lab analyze network \
  sample_data/aws/ec2/describe_security_groups.json \
  --input-format aws \
  --reachability-context sample_data/aws/ec2/network_reachability_context.json \
  --output reports/generated/network_findings.json \
  --summary-output reports/generated/network_analysis_summary.json
```

The summary uses [`analysis-summary-v1.0.schema.json`](../schemas/analysis-summary-v1.0.schema.json) and records:

| Field | Meaning |
| --- | --- |
| `module` | Analyzer that produced the result |
| `analyzer_version` | Installed lab version |
| `input_format` | `simplified` or `aws` |
| `input_file_count` | Primary and auxiliary evidence files consumed |
| `coverage_status` | `complete`, `partial`, or `empty` |
| `finding_count` | Findings produced by this run |
| `incident_count` | Correlated incidents produced by this run |
| `parameters` | Result-affecting dates, thresholds, and windows |
| `resource_coverage` | Discovered, evaluated, and skipped primary resources |
| `skipped_evidence` | Structured evidence omissions and their coverage effect |
| `warnings` | Non-fatal normalization and evidence-quality messages |

No runtime timestamp or source path is stored, so identical evidence and options produce identical summary JSON. Native IAM records its credential `as_of` date. CloudTrail records its failure threshold, failure window, and incident-correlation window.

## Status Semantics

`complete` means at least one primary resource was evaluated and no known skipped-evidence item has `affects_coverage: true`.

`partial` means at least one primary resource was evaluated, but a known evidence gap prevented one or more supported checks from running fully. Examples include an absent IAM policy document, unresolved network peer target, or missing CloudTrail MFA marker.

`empty` means no primary resource reached the analyzer. It takes precedence over partial because an empty run must not look like a successful zero-finding assessment.

An identical duplicate CloudTrail record is counted as skipped evidence with `affects_coverage: false`: the event is analyzed once and no distinct evidence is lost. A conflicting duplicate in simplified input affects coverage because only the first record reaches the current detector path.

## Primary Resources

| Module | Counted Resources |
| --- | --- |
| IAM | Users, groups, roles, and the root account |
| Storage | S3 buckets |
| Network | Security groups |
| CloudTrail | Unique event records |

Skipped evidence can be narrower than a primary resource. For example, all four security groups can be evaluated while a prefix-list target remains unresolved. The security-group count stays `4/4`, while the structured skipped-evidence entry makes the overall status `partial`.

## Report Integrity

Pass summaries to the report command with repeatable `--analysis-summary` options. The report verifies each module's declared finding and incident totals against the supplied files before rendering coverage. Once any summary is supplied, every module represented by the supplied findings or incidents must have a summary. A missing summary, incident file, or mismatched findings file therefore fails instead of producing a misleading report.

Coverage is evidence-relative. `complete` does not prove that an AWS export was current, authorized, unfiltered, account-wide, or comprehensive outside the documented contracts. A zero-finding complete run means only that the supported checks found no issues in the supplied evidence.
