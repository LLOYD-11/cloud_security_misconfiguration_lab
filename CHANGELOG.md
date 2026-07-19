# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added

- A post-v2.1 M10-M14 roadmap and requirement-to-evidence plan for verified
  boundary fixes, runtime hardening, independent evaluation, application
  presentation, and the final application release.

### Changed

- CloudTrail change rules now require the expected AWS `eventSource` together
  with the supported API name, preventing cross-service name collisions from
  producing findings.
- Simplified CloudTrail inputs now reject conflicting records that share an
  `eventID` instead of silently analyzing whichever record appeared first;
  identical duplicates continue to be analyzed once.
- Markdown reports now render artifact-derived prose, headings, code spans,
  table cells, references, and source paths through context-aware boundaries so
  model-valid text cannot alter the fixed report structure.
- Remediation rationale is now format-neutral plain text; Markdown syntax is
  owned exclusively by the report renderer.

## 2.1.0 - 2026-07-19

### Added

- Requirement-to-evidence traceability for the original M0-M9 upgrade plan.
- Findings v2 with deterministic IDs, first-class confidence, account, Region,
  UTC observation time, and structured source-evidence references.
- Strict v1-to-v2 finding migration that preserves unavailable provenance as
  explicit unknown or null values.
- CLI `--region` and `--observed-at` provenance defaults, with
  evidence-specific context taking precedence.
- A versioned, SHA-256-verified provenance manifest for every synthetic
  AWS-shaped fixture.
- Python 3.12 CI coverage between the supported 3.10 and 3.13 endpoints.
- Exact old/new CloudTrail failure-window equivalence tests, explicit boundary
  cases, and a deterministic 10,000-point structural operation bound.
- A versioned benchmark manifest mapping all 35 rules to positive, boundary,
  hardened-negative, and native-malformed evidence with exact expectations,
  false-positive rationale, and unsupported-evidence declarations.
- Deterministic small and large scale corpora, machine-readable benchmark
  results, calibrated memory and amplification budgets, and published reference
  measurements.
- Independent 90% statement and 85% branch coverage gates backed by
  machine-readable coverage evidence.
- A reviewer-focused README with CI and runtime badges, concise tested results,
  a real report preview, a four-step pipeline walkthrough, and engineering
  learning reflections.
- A five-minute demonstration guide for presenting the evidence flow, attack
  sequence, remediation model, assurance checks, and safety boundary.

### Changed

- Restored the original milestone numbering and recorded the remaining v2.1.0
  completion scope without changing the immutable v2.0.0 release.
- Reports, remediation plans, and timelines now consume finding-level
  confidence and expose first-class provenance.
- Native S3 normalization now preserves `BucketRegion`.
- CloudTrail failure-spike detection and incident correlation now keep account
  boundaries separate when multi-account evidence is supplied.
- CloudTrail failure-spike detection now uses a monotonic bounded-window scan
  after per-group sorting instead of repeatedly rescanning ordered suffixes.
- CI now runs the complete functional, fault-tolerance, and scale benchmark
  suite across Python 3.10, 3.12, and 3.13 without an unstable wall-clock gate.

## 2.0.0 - 2026-07-17

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
- Native EC2 `DescribeSecurityGroups` normalization with strict identity, protocol, port, CIDR, and pagination validation.
- A versioned native EC2 schema, AWS-shape security-group sample, normalized evidence export, CI pipeline verification, and regression tests.
- Native CloudTrail `Records` normalization for multiple JSON and gzip log files, with event-version, timestamp, identity, account, and GUID validation.
- AWS-shape CloudTrail log samples, a versioned native schema, duplicate-event warnings, conflicting-event rejection, and native pipeline verification.
- IAM rules for broad `NotAction` and `NotResource` allows, stale active credentials, root credentials, and unrestricted permissions boundaries.
- IAM environment evidence for groups and members, password usage, root posture, policy origin, and resolved permissions boundaries.
- S3 Object Ownership normalization and an ACL-enabled ownership posture rule.
- S3 public-policy condition analysis for documented fixed-value identity, account, network, VPC, source ARN, and data access point guardrails.
- Storage policy support for broad `NotPrincipal`, `NotAction`, and `NotResource` statements.
- A protocol-aware 20-service network exposure catalog covering remote administration, databases, data services, and cloud control planes.
- A versioned optional network reachability context with direction-specific status, explicit scope, assessment method, timestamp, evidence, and related resource IDs.
- Strict reachability-context normalization, partial-coverage warnings, schema tests, sample evidence, and unified CLI support through `--reachability-context`.
- CloudTrail rules for password-only IAM console login, cloud credential creation, role trust changes, monitoring-control disablement, and KMS disruption.
- Deterministic CloudTrail incident correlation by actor, source, and bounded time window, with stable IDs, inherited severity, explicit confidence, and versioned JSON output.
- A shared incident model, Draft 2020-12 incident schema, report integration, sample attack-chain incidents, and CLI support through `--incidents-output` and `--incidents`.
- Versioned analysis summaries for input format, analyzer version, resource coverage, skipped evidence, warnings, finding counts, and incident counts.
- Coverage-aware report sections and CLI support through `--summary-output` and repeatable `--analysis-summary` inputs.
- A versioned catalog for all 35 built-in rules with allowed severities, evidence-to-rule confidence, confidence rationale, and qualified AWS Security Hub CSPM, CIS AWS Foundations Benchmark, and MITRE ATT&CK mappings.
- A `catalog` CLI subcommand with module filtering and Markdown or JSON output.
- Triggered-rule context in consolidated reports, strict built-in rule/module/severity validation, and explicit compatibility for uncataloged custom rules.
- Catalog schema, completeness, control-mapping, deterministic documentation, and wheel-content gates.
- Deterministic P0-P3 remediation prioritization across findings and incidents, with separate response and hardening work types, conservative incident linkage, and stable action IDs.
- A versioned remediation-plan contract, machine-readable CLI output, report integration, public prioritization documentation, and complete source-accounting tests.
- A deterministic CloudTrail attack timeline with stable entry IDs, conservative activity labels, explicit evidence omissions, exact incident linkage, and richer incident narratives.
- A versioned attack-timeline contract, machine-readable CLI output, report integration, public interpretation documentation, and CloudTrail rule-classification completeness tests.
- System architecture, design-decision, and release documentation for the v2 portfolio release.

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
- Network environments can preserve security-group and prefix-list peers plus owner, VPC, ARN, tag, and peering context without treating unresolved peers as public CIDRs.
- Unified analysis accepts multiple positional inputs for native CloudTrail while retaining single-file behavior for simplified and other native module inputs.
- IAM action-wildcard analysis now covers service and partial patterns independently from wildcard-resource findings.
- IAM cross-account trust severity now distinguishes public principals, unguarded external trust, and supported equality-based trust conditions.
- IAM MFA findings now require an active or compatibility-assumed console password, avoiding native-input false positives for programmatic-only users.
- Native IAM group policies are analyzed once at the group resource with member context instead of being copied into every member's direct-policy list.
- Storage ACL findings now account for `BucketOwnerEnforced`, while public-policy findings retain overbroad CIDRs, wildcard values, policy variables, negative operators, and `IfExists` conditions as public.
- Network findings now distinguish security-group permission paths from supplied end-to-end reachability conclusions. A valid `not_reachable` assessment lowers severity by one level without suppressing the latent configuration risk.
- CloudTrail findings preserve richer event metadata and failure-spike event IDs; assumed-role actors prefer stable session-issuer identity when available.

## 1.0.0 - 2026-06-30

- Added four offline AWS-style analyzers, a shared finding model, a Markdown report generator, sample data, and 21 unit tests.
