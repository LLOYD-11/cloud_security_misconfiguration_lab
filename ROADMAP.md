# Upgrade Roadmap

This is the canonical upgrade route for the Cloud Security
Misconfiguration Lab. It preserves the original M0-M9 identifiers; milestones
must not be renumbered or collapsed when work is summarized.

`v2.0.0` is an immutable, working release checkpoint. `v2.1.0` completes the
remaining provenance, performance, benchmark, and portfolio-presentation work
from the original upgrade plan. `v2.1.1` closes the verified M10 boundary
defects without widening the analyzer scope.

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

## Post-v2.1 Upgrade Route

The original M0-M9 route remains immutable and complete. The milestones below
extend the project from a deterministic synthetic lab into an independently
evaluated application project without renumbering or reopening the original
requirements.

Planned release checkpoints:

| Release | Milestones | Purpose |
| --- | --- | --- |
| `v2.1.1` | M10 | Close verified correctness and report-integrity defects. |
| `v2.2.0` | M11-M12 | Harden runtime boundaries and publish independent evaluation evidence. |
| `v2.3.0` | M13-M14 | Publish the research narrative and final application release. |

## M10: Verified Boundary Defects

Status: Complete in `v2.1.1`.

- [x] Match CloudTrail change rules on both AWS service source and event name.
- [x] Reject conflicting simplified CloudTrail records that share an `eventID`,
      while continuing to analyze identical duplicates once.
- [x] Preserve generated Markdown structure when finding, incident, summary, or
      source text contains Markdown control characters.
- [x] Validate the consumed structure of all simplified analyzer inputs at
      runtime and return stable user-facing errors.
- [x] Convert every verified defect into a regression test and search all
      equivalent entry points for the same failure mode.
- [x] Run the full release gate and publish `v2.1.1`.

## M11: Runtime and Supply-Chain Hardening

Status: Planned for `v2.2.0`.

- [ ] Define evidence-based limits for JSON size, decompressed gzip size,
      resource count, node count, and nesting depth.
- [ ] Fail closed on oversized, deeply nested, truncated, or malformed inputs.
- [ ] Pin GitHub Actions to immutable revisions and make development dependency
      resolution reproducible.
- [ ] Exercise every documented Python minor version in CI.
- [ ] Add Markdown, internal-link, and external-link validation.
- [ ] Publish a security policy, threat model, release checksums, an SBOM, and
      build-provenance evidence.

## M12: Independent External Evaluation

Status: Planned for `v2.2.0`.

- [ ] Publish a versioned evaluation protocol before running the analyzers.
- [ ] Build a provenance-tracked corpus of independent positive, hardened,
      boundary, and ambiguous IAM, S3, network, and CloudTrail cases.
- [ ] Establish ground truth independently from analyzer output and preserve
      sanitized native evidence with integrity hashes.
- [ ] Compare overlapping controls with an established external baseline without
      treating unsupported scope as a disagreement.
- [ ] Publish per-module true positives, false positives, false negatives, true
      negatives, precision, recall, F1, and complete disagreement analysis.
- [ ] Measure native/simplified equivalence and the effects of reachability
      context and incident correlation.
- [ ] Publish machine-readable evaluation results and a reproducible runner.

## M13: Research and Application Narrative

Status: Planned for `v2.3.0`.

- [ ] State one bounded research question and connect every public claim to
      architecture or evaluation evidence.
- [ ] Publish a concise technical case study with method, results, threats to
      validity, limitations, and future work.
- [ ] Identify personal contribution, important design changes, difficult
      defects, and lessons learned without overstating authorship.
- [ ] Reduce the main README to a reviewer-first project entry point and move
      detailed reference material into focused documents.
- [ ] Publish a short real-system demo and a one-page application summary.
- [ ] Make public author, project, version, and support information consistent.

## M14: Final Application Release

Status: Planned for `v2.3.0`.

- [ ] Reproduce installation, analysis, evaluation, and release from a clean
      clone and installed wheel.
- [ ] Complete final correctness, privacy, secret, license, link, documentation,
      and unsupported-claim reviews.
- [ ] Link every M10-M14 requirement to implementation, test, documentation, and
      commit evidence.
- [ ] Publish deterministic application artifacts and the final `v2.3.0`
      release with checksums, SBOM, and evaluation results.

## Definition of Done

The original upgrade route is complete only when:

- every M0-M9 milestone is marked Complete;
- each requirement has linked implementation, test, documentation, and commit evidence where applicable;
- the full local and GitHub Actions quality gates pass;
- generated artifacts remain deterministic and match their committed references;
- privacy, offline-safety, and known-limitations reviews pass; and
- the final release notes describe both delivered behavior and residual limitations.
