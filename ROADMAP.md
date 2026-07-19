# Upgrade Roadmap

This is the canonical upgrade route for the Cloud Security
Misconfiguration Lab. It preserves the original M0-M9 identifiers; milestones
must not be renumbered or collapsed when work is summarized.

`v2.0.0` is an immutable, working release checkpoint. `v2.1.0` completes the
remaining provenance, performance, benchmark, and portfolio-presentation work
from the original upgrade plan.

Detailed requirement, artifact, test, and commit evidence is maintained in
[Upgrade traceability](docs/traceability.md).

## Status Definitions

| Status | Meaning |
| --- | --- |
| Complete | The planned behavior, tests, and documentation are present. |
| Substantially complete | The main capability is present, but named acceptance criteria remain open. |
| In progress | Important planned deliverables are still missing. |

## M0: Freeze v1 and Record the Baseline

Status: Complete in `v1.0.0`.

- [x] Preserve the original working project as the `v1.0.0` tag at commit `8e8f86e`.
- [x] Record the public roadmap, changelog, and known limitations.
- [x] Preserve the v1 sample report and passing test baseline.
- [x] Perform upgrade work on a dedicated branch.

## M1: Correctness and Contract Hardening

Status: Complete in `v2.0.0`.

- [x] Add regression tests for verified IAM, S3, network, CloudTrail, and finding-contract defects.
- [x] Correct principal and trust parsing, MFA-condition handling, S3 action wildcards, public-principal handling, protocol and CIDR classification, and CloudTrail outcome semantics.
- [x] Enforce finding schema versions, required fields, finding counts, and severity values.
- [x] Preserve deterministic finding order and reporting output.

## M2: Engineering Foundation, CLI, Schema, and CI

Status: Complete in `v2.1.0`.

- [x] Add installable package metadata and optional development dependencies.
- [x] Add the unified `analyze`, `report`, `demo`, and `catalog` CLI workflows.
- [x] Publish versioned JSON Schema contracts and Python validation.
- [x] Add lint, strict type, unit, branch-coverage, package-build, and deterministic end-to-end CI checks.
- [x] Keep the original module scripts as compatibility entry points.
- [x] Add first-class finding provenance: stable finding ID, account, region, observation time, and source evidence.
- [x] Define the compatibility and migration behavior for the revised finding contract.
- [x] Add Python 3.12 to the CI matrix so the documented 3.10-3.13 support range is exercised at its midpoint.

## M3: Native AWS Evidence Adapters

Status: Complete in `v2.1.0`.

- [x] Normalize IAM account-authorization details and credential-report evidence.
- [x] Normalize S3 account and bucket security evidence.
- [x] Normalize EC2 `DescribeSecurityGroups` evidence.
- [x] Read CloudTrail `Records` payloads from multiple JSON and gzip files.
- [x] Keep analyzer inputs stable by normalizing AWS-shaped evidence into canonical environments.
- [x] Document collection commands, validation behavior, and offline safety boundaries.
- [x] Add a manifest for each sanitized AWS-shaped fixture that records its operation, shape, sanitization, and expected coverage.

## M4: IAM Analyzer v2

Status: Complete in `v2.0.0`.

- [x] Analyze wildcard and partial-wildcard actions, `NotAction`, `NotResource`, groups, managed and inline policies, and permissions boundaries.
- [x] Analyze root posture, access-key age and use, password activity, and MFA without assuming every IAM user has console access.
- [x] Evaluate cross-account trust by principal and supported condition type.
- [x] Publish confidence rationale and qualified AWS Security Hub, CIS AWS Foundations Benchmark, and MITRE ATT&CK mappings.

## M5: Storage and Network Analyzers v2

Status: Complete in `v2.0.0` within the documented offline evidence boundary.

- [x] Combine account-level and bucket-level S3 Block Public Access evidence.
- [x] Evaluate Object Ownership, ACL effectiveness, public-policy conditions, encryption posture, and versioning.
- [x] Classify IPv4 and IPv6 CIDRs with protocol-aware port and service analysis.
- [x] Detect broad inbound services and unrestricted outbound paths without duplicate findings.
- [x] Accept optional end-to-end reachability context and preserve uncertainty instead of claiming live reachability.
- [x] Document unmodeled organization policy and cross-policy authorization limits.

## M6: CloudTrail Detection and Attack-Chain Correlation

Status: Complete in `v2.1.0`.

- [x] Validate event identity, time, source, outcome, and duplicate `eventID` behavior.
- [x] Detect root login, MFA removal, security-control changes, credential creation, policy and trust changes, monitoring disablement, KMS disruption, and API-failure spikes.
- [x] Correlate eligible events into deterministic incidents by actor, source, and time window.
- [x] Generate an evidence-based chronological attack timeline with explicit omissions.
- [x] Replace the quadratic API-failure spike window scan with a linear or near-linear bounded-window implementation.
- [x] Add performance regression tests proving identical findings at scale.

## M7: Professional Report and Risk Model

Status: Complete in `v2.0.0`.

- [x] Add an executive summary, top risks, severity totals, resource context, and module coverage.
- [x] Distinguish evaluated, skipped, partial, empty, and complete analysis coverage.
- [x] Include rule confidence, qualified control mappings, evidence, impact, and remediation.
- [x] Prioritize deterministic P0-P3 response and hardening actions across findings and incidents.
- [x] Include attack-chain incidents, a chronological timeline, methodology, scope, assumptions, and limitations.
- [x] Keep the generated sample report deterministic.

## M8: Tests, Benchmark, Performance, and Fault Tolerance

Status: Complete in `v2.1.0`.

- [x] Build broad unit, contract, schema, CLI, native-adapter, integration, malformed-input, duplicate-input, and deterministic-output coverage.
- [x] Run branch-enabled coverage and enforce the current CI quality gate.
- [x] Publish a machine-readable benchmark manifest with exact expected findings for curated positive, negative, boundary, and malformed cases.
- [x] Document false-positive rationale and intentionally unsupported evidence for benchmark cases.
- [x] Add defined small and large corpora with repeatable runtime and memory measurements.
- [x] Add performance and fault-tolerance acceptance budgets to CI without introducing unstable wall-clock tests.
- [x] Record separate line and branch coverage results against the original 90% and 85% targets.

## M9: GitHub Application Presentation and Final v2 Release

Status: Complete in `v2.1.0`.

- [x] Publish an AWS-only first-screen summary, quick start, sample results, architecture, rule catalog, design decisions, and release notes.
- [x] Publish an immutable `v2.0.0` tag and GitHub release.
- [x] Preserve an auditable milestone-oriented commit history.
- [x] Add repository About metadata and focused GitHub topics.
- [x] Add a CI status badge and a concise tested-results block to the README.
- [x] Add a legible report preview and a short demo walkthrough.
- [x] Add a concise "What I learned" section for application reviewers.
- [x] Complete every open M0-M9 acceptance item, then publish `v2.1.0`.

## v2.1 Completion Sequence

1. **C0 - Governance (complete):** restore M0-M9 and add requirement-to-evidence traceability.
2. **C1 - Provenance (complete):** complete M2 and M3 finding provenance, contract migration, Python 3.12 CI, and fixture manifests.
3. **C2 - Detection performance (complete):** complete the M6 failure-window optimization and equivalence tests.
4. **C3 - Benchmarking (complete):** complete M8 benchmark, scale, resilience, and coverage evidence.
5. **C4 - Portfolio presentation (complete):** complete the remaining M9 README, visual, and repository-metadata work.
6. **C5 - Release (complete):** run the full release gate and publish `v2.1.0`.

## Definition of Done

The original upgrade route is complete only when:

- every M0-M9 milestone is marked Complete;
- each requirement has linked implementation, test, documentation, and commit evidence where applicable;
- the full local and GitHub Actions quality gates pass;
- generated artifacts remain deterministic and match their committed references;
- privacy, offline-safety, and known-limitations reviews pass; and
- the final release notes describe both delivered behavior and residual limitations.
