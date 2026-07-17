# Upgrade Roadmap

The v2 roadmap focuses on evidence quality and compatibility before adding more detection rules.

## Milestone 1: Reliability Baseline

Status: Complete.

- Convert confirmed false positives and false negatives into regression tests.
- Enforce finding-schema versions and severity values.
- Distinguish failed, risk-increasing, and risk-reducing CloudTrail activity.

## Milestone 2: Engineering Foundation

Status: Complete.

- Add package metadata, a unified CLI, explicit data contracts, and GitHub Actions.
- Keep the current module scripts as compatibility entry points.
- Add automated type, style, test, coverage, and end-to-end checks.

## Milestone 3: Native AWS Inputs

Status: Complete.

- [x] Normalize IAM authorization details and credential reports.
- [x] Normalize S3 security API responses.
- [x] Normalize EC2 `DescribeSecurityGroups` output.
- [x] Read CloudTrail `Records` payloads, multiple files, and gzip archives.

## Milestone 4: Detection Depth

Status: Complete.

- [x] Improve IAM wildcard, trust-condition, group, boundary, and credential analysis.
- [x] Add S3 policy-condition and ownership-control context.
- [x] Expand the network service catalog and add optional reachability context.
- [x] Expand CloudTrail rules and correlate related events into incidents.

## Milestone 5: Reporting and Portfolio Release

Status: In Progress.

- [x] Publish versioned analysis summaries for evaluated resources, skipped evidence, warnings, and coverage status.
- [x] Add a versioned rule catalog with confidence and qualified control mappings.
- [x] Add prioritized remediation across findings and correlated incidents.
- Add an attack timeline and richer explanatory context to the deterministic sample report.
- Publish architecture, rule-catalog, and design-decision documentation with a v2 release.
