# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added

- Regression tests for IAM trust, MFA conditions, S3 action wildcards, storage principals, network protocols and CIDRs, CloudTrail outcomes, duplicate events, and finding-schema validation.
- Public upgrade roadmap and known-limitations documentation.
- Optional `--report-date` support for reproducible sample reports.
- Installable Python package metadata and the `cloud-security-lab` unified CLI.
- Versioned Draft 2020-12 JSON Schema contracts for all simplified inputs and findings.
- GitHub Actions checks for Python 3.10 and 3.13.
- Ruff linting, strict production type checks, branch coverage, package builds, and deterministic end-to-end verification.
- Native IAM normalization for AWS account authorization details, Base64 JSON or decoded CSV credential reports, managed policies, group inheritance, and role trust policies.
- A native IAM input schema, AWS-shape sample evidence, normalization warnings, and optional normalized evidence export from the unified CLI.
- Native S3 evidence-bundle normalization for bucket inventory, effective Block Public Access, ACLs, policies, default encryption, and versioning.
- Strict S3 collection-error and bucket-coverage validation, an AWS-shape sample, a versioned bundle schema, and native storage CLI verification.
- Support for the 2026 S3 `BlockedEncryptionTypes` response shape while preserving the universal SSE-S3 baseline.

### Changed

- IAM trust analysis now evaluates AWS and federated principals individually and excludes AWS service principals from cross-account findings.
- IAM MFA-condition analysis now checks the value associated with the MFA condition key instead of searching serialized condition text.
- S3 write analysis recognizes scoped wildcard actions such as `s3:Put*`.
- Storage encryption findings now describe the absence of an explicit key-management posture without claiming that S3 baseline encryption is disabled.
- Network analysis is protocol-aware and uses explicit non-public ranges to classify internet-wide and exceptionally broad public CIDRs consistently across supported Python versions.
- Storage ACL and policy exposure rules now respect effective `IgnorePublicAcls` and `RestrictPublicBuckets` controls.
- CloudTrail change findings require successful, risk-increasing API activity and deduplicate explicit event IDs.
- Shared finding files now enforce supported schema versions, declared finding counts, required fields, field types, and valid severities.
- Unversioned legacy finding lists are rejected by the report pipeline.
- Sample data and schemas are included in built distributions so the demo command works outside a source checkout.

## 1.0.0 - 2026-06-30

- Added four offline AWS-style analyzers, a shared finding model, a Markdown report generator, sample data, and 21 unit tests.
