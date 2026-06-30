# CloudTrail-Style Event Detector

This module analyzes offline CloudTrail-style event data for suspicious cloud API activity.

It does not call AWS APIs or require cloud credentials. The sample data models audit events commonly reviewed during cloud incident triage.

## Detection Rules

| Rule | Severity | Description |
| --- | --- | --- |
| `CLD-001` | Critical | Root account console login |
| `CLD-002` | High | MFA device disabled or deleted |
| `CLD-003` | Medium | Security group configuration changed |
| `CLD-004` | High | Bucket access policy changed |
| `CLD-005` | High | IAM policy configuration changed |
| `CLD-006` | Medium | Repeated API failures from one actor and source |

The failed API detector uses a default threshold of 5 failed API calls within 10 minutes for the same actor and source IP.

Each finding uses the shared schema and includes AWS CloudTrail, AWS IAM, or MITRE ATT&CK references where applicable.

## Run

```bash
python3 cloudtrail_detector/detector.py \
  sample_data/cloudtrail/sample_cloudtrail_events.json
```

Export JSON:

```bash
python3 cloudtrail_detector/detector.py \
  sample_data/cloudtrail/sample_cloudtrail_events.json \
  --output reports/generated/cloudtrail_findings.json
```

The threshold can be tuned:

```bash
python3 cloudtrail_detector/detector.py \
  sample_data/cloudtrail/sample_cloudtrail_events.json \
  --failure-threshold 5 \
  --failure-window-minutes 10
```

The exported JSON can be passed directly to `report_generator/generate_report.py`.

## Test

```bash
python3 -m unittest cloudtrail_detector.test_detector
```
