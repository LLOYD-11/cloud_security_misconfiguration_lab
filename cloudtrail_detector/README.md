# CloudTrail-Style Event Detector

This module analyzes offline CloudTrail-style event data for suspicious cloud API activity.

It does not call AWS APIs or require cloud credentials. The simplified model can be analyzed directly, while the unified CLI can normalize one or more native CloudTrail `Records` files in JSON or gzip format.

## Detection Rules

| Rule | Severity | Description |
| --- | --- | --- |
| `CLD-001` | Critical | Root account console login |
| `CLD-002` | High | MFA device disabled or deleted |
| `CLD-003` | Medium | Successful security group authorization change |
| `CLD-004` | High | Successful bucket access change that can weaken controls |
| `CLD-005` | High | Successful IAM policy change that can add access |
| `CLD-006` | Medium | Repeated API failures from one actor and source |
| `CLD-007` | High | Successful IAM user console login explicitly recorded without MFA |
| `CLD-008` | High | Persistent credential such as an access key or login profile created |
| `CLD-009` | High | Role trust policy changed |
| `CLD-010` | High/Critical | Audit or threat-detection control disabled |
| `CLD-011` | High/Critical | KMS key disabled or scheduled for deletion |

The failed API detector uses a default threshold of 5 failed API calls within 10 minutes for the same actor and source IP.

Failed API calls do not produce findings that claim a configuration changed. Risk-reducing actions such as revoking ingress, deleting a bucket policy, or detaching an IAM policy are also excluded from the risk-increasing change rules. Duplicate events with the same `eventID` are analyzed once.

Each finding uses the shared schema and includes AWS CloudTrail, AWS IAM, or MITRE ATT&CK references where applicable.

## Incident Correlation

The detector can also export versioned correlated incidents. By default it groups eligible signals from the same actor and source within a 30-minute bounded window.

A multi-signal incident requires at least two distinct rule IDs and two event IDs. The already-aggregated `CLD-006` failure spike may form an incident by itself. Incident severity inherits the highest constituent finding and is never raised solely by event count.

See [CloudTrail incident correlation](../docs/incident-correlation.md) for the identity fallback order, deterministic incident IDs, confidence model, and evidence limitations.

## Run

```bash
python3 cloudtrail_detector/detector.py \
  sample_data/cloudtrail/sample_cloudtrail_events.json
```

Export JSON:

```bash
python3 cloudtrail_detector/detector.py \
  sample_data/cloudtrail/sample_cloudtrail_events.json \
  --output reports/generated/cloudtrail_findings.json \
  --incidents-output reports/generated/cloudtrail_incidents.json
```

The threshold can be tuned:

```bash
python3 cloudtrail_detector/detector.py \
  sample_data/cloudtrail/sample_cloudtrail_events.json \
  --failure-threshold 5 \
  --failure-window-minutes 10 \
  --correlation-window-minutes 30
```

The exported JSON can be passed directly to `report_generator/generate_report.py`.

Analyze the bundled native JSON and gzip log files through the unified CLI:

```bash
python3 -m cloud_security_lab analyze cloudtrail \
  sample_data/aws/cloudtrail/111122223333_CloudTrail_20260630T0200Z_part1.json \
  sample_data/aws/cloudtrail/111122223333_CloudTrail_20260630T0300Z_part2.json.gz \
  --input-format aws \
  --normalized-output reports/generated/normalized_cloudtrail_environment.json \
  --output reports/generated/cloudtrail_findings.json \
  --incidents-output reports/generated/cloudtrail_incidents.json
```

See [`docs/native-aws-inputs.md`](../docs/native-aws-inputs.md) for collection guidance, duplicate-event handling, and evidence boundaries.

## Test

```bash
python3 -m unittest cloudtrail_detector.test_detector
```
