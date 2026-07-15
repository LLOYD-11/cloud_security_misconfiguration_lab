# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added

- Regression tests for IAM trust, MFA conditions, S3 action wildcards, storage principals, network protocols and CIDRs, CloudTrail outcomes, duplicate events, and finding-schema validation.
- Public upgrade roadmap and known-limitations documentation.
- Optional `--report-date` support for reproducible sample reports.

### Changed

- IAM trust analysis now evaluates AWS and federated principals individually and excludes AWS service principals from cross-account findings.
- IAM MFA-condition analysis now checks the value associated with the MFA condition key instead of searching serialized condition text.
- S3 write analysis recognizes scoped wildcard actions such as `s3:Put*`.
- Storage encryption findings now describe the absence of an explicit key-management posture without claiming that S3 baseline encryption is disabled.
- Network analysis is protocol-aware and distinguishes internet-wide from exceptionally broad public CIDRs.
- CloudTrail change findings require successful, risk-increasing API activity and deduplicate explicit event IDs.
- Shared finding files now enforce supported schema versions, declared finding counts, required fields, field types, and valid severities.
- Unversioned legacy finding lists are rejected by the report pipeline.

## 1.0.0 - 2026-06-30

- Added four offline AWS-style analyzers, a shared finding model, a Markdown report generator, sample data, and 21 unit tests.
