# Upgrade Traceability

This document maps the original M0-M9 upgrade requirements to repository
evidence. It exists to prevent milestone renumbering, scope drift, and
unsupported completion claims.

The canonical plan is [ROADMAP.md](../ROADMAP.md). `v2.0.0` at commit
`7acfda6` is an immutable checkpoint. `v2.1.0` closes the remaining requirements
from the original M0-M9 plan.

## Status Legend

| Status | Meaning |
| --- | --- |
| Complete | Implementation, verification, and public documentation evidence are present. |
| Partial | Meaningful implementation exists, but at least one acceptance criterion remains open. |
| Open | The planned deliverable has not been implemented. |

## Release Checkpoints

| Checkpoint | Reference | Purpose |
| --- | --- | --- |
| `v1.0.0` | `8e8f86e` | Frozen original four-analyzer project and sample report. |
| `v2.0.0` | `7acfda6` | Working reliability, native-input, detection-depth, and reporting release. |
| `v2.1.0` | Tag `v2.1.0` | Completion release for every remaining M0-M9 acceptance item. |

Planned post-v2.1 checkpoints are `v2.1.1` for M10, `v2.2.0` for
M11-M12, and `v2.3.0` for M13-M14. They become release checkpoints in this
table only after their tags and release evidence exist.

## M0: Freeze v1 and Record the Baseline

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M0-R1 | Preserve the original working release. | Complete | Git tag `v1.0.0`; commit `8e8f86e`. |
| M0-R2 | Publish roadmap, changelog, and known limitations. | Complete | [Roadmap](../ROADMAP.md), [changelog](../CHANGELOG.md), and [known limitations](known-limitations.md); reliability commit `c673c29`. |
| M0-R3 | Preserve baseline tests and the sample report. | Complete | Analyzer test modules and [sample report](../reports/cloud_security_report_sample.md) in `v1.0.0`. |
| M0-R4 | Isolate upgrade work from the release branch. | Complete | `upgrade/v2-reliability` history from `v1.0.0` through `v2.0.0`. |

## M1: Correctness and Contract Hardening

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M1-R1 | Convert verified defects into regression tests. | Complete | Analyzer test modules under `iam_analyzer/`, `storage_analyzer/`, `network_analyzer/`, and `cloudtrail_detector/`; commit `c673c29`. |
| M1-R2 | Correct IAM principal, trust, and MFA semantics. | Complete | [IAM analyzer](../iam_analyzer/analyzer.py) and its tests; commits `c673c29` and `4cfc489`. |
| M1-R3 | Correct S3 action wildcard and public-principal semantics. | Complete | [Storage analyzer](../storage_analyzer/analyzer.py) and its tests; commits `c673c29` and `a094672`. |
| M1-R4 | Correct protocol and CIDR classification. | Complete | [Network analyzer](../network_analyzer/analyzer.py) and its tests; commits `c673c29` and `b5dda3f`. |
| M1-R5 | Distinguish failed, risk-increasing, and risk-reducing CloudTrail activity. | Complete | [CloudTrail detector](../cloudtrail_detector/detector.py) and its tests; commit `c673c29`. |
| M1-R6 | Enforce versioned finding files and strict severity values. | Complete | [Finding model](../cloud_findings/finding.py), [finding schema](../schemas/findings-v1.0.schema.json), and [contract tests](../tests/test_contracts.py); commit `0d981ba`. |

## M2: Engineering Foundation, CLI, Schema, and CI

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M2-R1 | Add installable package metadata. | Complete | [pyproject.toml](../pyproject.toml); commit `0d981ba`. |
| M2-R2 | Add unified analyze, report, demo, and catalog workflows. | Complete | [CLI](../cloud_security_lab/cli.py), CLI tests, and [README commands](../README.md); commits `0d981ba` and `5747c00`. |
| M2-R3 | Publish versioned data contracts and validation warnings. | Complete | [Data contracts](data-contracts.md), `schemas/`, Python model validation, and normalizer tests. |
| M2-R4 | Add stable finding identity and first-class account, region, time, confidence, and source provenance. | Complete | [Finding model](../cloud_findings/finding.py), [findings v2 schema](../schemas/findings-v2.0.schema.json), analyzer propagation, report rendering, and v1 migration tests. |
| M2-R5 | Run lint, strict typing, tests, coverage, build, and end-to-end checks in CI. | Complete | [CI workflow](../.github/workflows/ci.yml) and [engineering checks](engineering.md); commit `0d981ba`. |
| M2-R6 | Exercise Python 3.10, 3.12, and 3.13. | Complete | The [CI matrix](../.github/workflows/ci.yml) runs quality and end-to-end checks on all three documented versions. |
| M2-R7 | Preserve original module entry points. | Complete | Legacy CLI tests in [tests/test_legacy_clis.py](../tests/test_legacy_clis.py). |

## M3: Native AWS Evidence Adapters

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M3-R1 | Normalize IAM authorization details and credential reports. | Complete | IAM normalizer, native schema, AWS-shaped sample, and tests; commit `fb70b50`. |
| M3-R2 | Normalize S3 account and bucket evidence. | Complete | S3 normalizer, native schema, AWS-shaped sample, and tests; commit `53d708d`. |
| M3-R3 | Normalize EC2 security-group evidence. | Complete | EC2 normalizer, native schema, AWS-shaped sample, and tests; commit `a8b68b8`. |
| M3-R4 | Normalize multiple CloudTrail JSON and gzip files. | Complete | CloudTrail normalizer, native schema, AWS-shaped samples, and tests; commit `d399dc6`. |
| M3-R5 | Keep analyzers independent of native AWS response shapes. | Complete | Normalizers emit the versioned canonical environments documented in [native AWS inputs](native-aws-inputs.md). |
| M3-R6 | Document direct collection and offline safety. | Complete | Collection commands and safety boundaries in [native AWS inputs](native-aws-inputs.md) and [README](../README.md). |
| M3-R7 | Record fixture source shape, sanitization, and expected coverage. | Complete | [AWS fixture manifest](../sample_data/aws/fixture-manifest-v1.0.json), [manifest schema](../schemas/aws-fixture-manifest-v1.0.schema.json), exact-inventory and SHA-256 contract tests, and [native input documentation](native-aws-inputs.md). |

## M4: IAM Analyzer v2

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M4-R1 | Analyze wildcard actions, `NotAction`, `NotResource`, and resource scope. | Complete | IAM analyzer and tests; commit `4cfc489`. |
| M4-R2 | Analyze users, groups, managed and inline policies, and boundaries without double counting. | Complete | IAM analyzer, native IAM normalizer, and regression tests. |
| M4-R3 | Analyze root, credential age and use, password activity, and MFA. | Complete | IAM rules and sample findings; commit `4cfc489`. |
| M4-R4 | Evaluate external trust principals and supported conditions. | Complete | IAM trust tests and rule-catalog rationale. |
| M4-R5 | Publish qualified security-control mappings. | Complete | [Rule catalog](rule-catalog.md); commit `5747c00`. |

## M5: Storage and Network Analyzers v2

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M5-R1 | Combine account-level and bucket-level S3 Block Public Access. | Complete | S3 native normalizer, tests, and [native-input documentation](native-aws-inputs.md). |
| M5-R2 | Model Object Ownership, ACL effectiveness, policy conditions, encryption, and versioning. | Complete | Storage analyzer and tests; commit `a094672`. |
| M5-R3 | Classify broad IPv4 and IPv6 CIDRs with protocol and service context. | Complete | Network analyzer and tests; commits `b5dda3f` and `a8c49d9`. |
| M5-R4 | Avoid duplicate all-protocol and sensitive-service findings. | Complete | Network boundary regression tests. |
| M5-R5 | Preserve supplied reachability evidence and uncertainty. | Complete | Reachability schema, analyzer tests, and [design decisions](design-decisions.md); commit `a8c49d9`. |
| M5-R6 | State offline authorization and organization-policy limits. | Complete | [Known limitations](known-limitations.md). |

## M6: CloudTrail Detection and Attack-Chain Correlation

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M6-R1 | Validate event identity, timestamp, source, outcome, and duplicate IDs. | Complete | CloudTrail normalizer and detector tests; commits `d399dc6` and `51af0b7`. |
| M6-R2 | Detect identity, network, storage, monitoring, IAM, credential, and KMS risk changes. | Complete | CloudTrail detector, tests, and [rule catalog](rule-catalog.md); commit `51af0b7`. |
| M6-R3 | Correlate events into deterministic incidents. | Complete | [Correlation engine](../cloudtrail_detector/correlation.py), incident contract, tests, and [correlation documentation](incident-correlation.md). |
| M6-R4 | Produce an evidence-based attack timeline. | Complete | Timeline package, tests, schema, and [timeline documentation](attack-timeline.md); commit `ea5b59e`. |
| M6-R5 | Use a linear or near-linear bounded failure window. | Complete | Monotonic two-pointer implementation in the [CloudTrail detector](../cloudtrail_detector/detector.py), exact old/new finding-equivalence and structural operation-bound tests in the [detector test suite](../cloudtrail_detector/test_detector.py), and published [performance evidence](detection-performance.md). |

## M7: Professional Report and Risk Model

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M7-R1 | Report executive totals, top risks, affected resources, and module coverage. | Complete | [Report generator](../report_generator/generate_report.py) and committed sample report. |
| M7-R2 | Distinguish evaluated, skipped, complete, partial, and empty coverage. | Complete | Analysis-summary contract, tests, and [coverage documentation](analysis-coverage.md); commit `a7a1702`. |
| M7-R3 | Publish confidence and qualified control mappings. | Complete | Versioned rule catalog, schema, tests, and generated documentation; commit `5747c00`. |
| M7-R4 | Prioritize response and hardening work. | Complete | Remediation package, schema, tests, and [prioritization documentation](remediation-prioritization.md); commit `f733def`. |
| M7-R5 | Include incidents, timeline, methodology, assumptions, and limitations. | Complete | Deterministic sample report and related public documentation; commits `ea5b59e` and `7acfda6`. |

## M8: Tests, Benchmark, Performance, and Fault Tolerance

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M8-R1 | Cover every rule with positive, negative, boundary, and malformed cases. | Complete | The [benchmark manifest](../cloud_benchmarks/benchmark-manifest-v1.0.json) maps all 35 rules to positive, boundary, hardened-negative, and native-malformed cases; contract tests verify the complete matrix. |
| M8-R2 | Verify native fixtures, CLI, schemas, golden output, and integration. | Complete | Normalizer tests, CLI tests, contract tests, legacy CLI tests, and deterministic demo comparison in CI. |
| M8-R3 | Verify duplicate, invalid, incomplete, and deterministic behavior. | Complete | Analysis-summary, normalizer, finding, incident, remediation, timeline, and report tests. |
| M8-R4 | Verify large-input behavior and define performance budgets. | Complete | Eight deterministic scale profiles exercise 100 to 10,000 inputs with exact counts, 0.10 amplification ceilings, repeated-output equality, 16/64 MiB traced-memory budgets, CI execution, and published [measurements](benchmarking.md). |
| M8-R5 | Demonstrate at least 90% line and 85% branch coverage. | Complete | The independent coverage gate records 4,477/4,703 statements (95.19%) and 1,694/1,900 branches (89.16%); see [benchmarking](benchmarking.md) and [engineering checks](engineering.md). |
| M8-R6 | Publish exact benchmark expectations and false-positive rationale. | Complete | The versioned [manifest](../cloud_benchmarks/benchmark-manifest-v1.0.json), [schemas](data-contracts.md), and [methodology](benchmarking.md) publish exact signatures, false-positive rationale, unsupported evidence, and fail-closed error contracts. |

## M9: GitHub Application Presentation and Final v2 Release

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M9-R1 | Present an AWS-only summary, architecture, commands, results, and sample report. | Complete | [README](../README.md), [architecture](architecture.md), [design decisions](design-decisions.md), and sample report. |
| M9-R2 | Publish rule-catalog and release documentation. | Complete | Rule-catalog documentation plus the [v2.0.0](release-v2.0.0.md) and [v2.1.0](release-v2.1.0.md) release notes. |
| M9-R3 | Publish an immutable GitHub release. | Complete | Tag and release `v2.0.0`; release workflow from commit `7acfda6`. |
| M9-R4 | Configure repository About metadata and focused topics. | Complete | The public [repository About panel](https://github.com/LLOYD-11/cloud_security_misconfiguration_lab) includes a concise description, sample-report homepage, and ten focused AWS, security, and engineering topics. |
| M9-R5 | Show CI status and concise tested results in the README. | Complete | The [README](../README.md) shows the live CI badge, supported Python matrix, exact test and independent statement/branch coverage results, benchmark outcomes, and distribution checks. |
| M9-R6 | Add a report preview, demo walkthrough, and learning reflection. | Complete | The [report preview](assets/report-preview.svg), [five-minute demo](demo-walkthrough.md), and [README learning reflections](../README.md#what-i-learned) present real project evidence without widening the documented claims. |
| M9-R7 | Preserve milestone review history and publish the completion release. | Complete | The milestone-oriented `upgrade/v2.1-completion` history, annotated `v2.1.0` tag, matching release notes, and gated release workflow preserve and publish the completion evidence. |

## M10: Verified Boundary Defects

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M10-R1 | Match CloudTrail change rules on service source and event name. | Open | Planned detector mapping, wrong-source regression matrix, catalog review, and compatibility documentation. |
| M10-R2 | Reject conflicting simplified duplicate event IDs while deduplicating identical records. | Open | Planned shared duplicate validator, detector and CLI regression tests, and coverage-summary update. |
| M10-R3 | Preserve Markdown report structure for untrusted artifact text. | Open | Planned context-aware renderer escaping and adversarial report tests. |
| M10-R4 | Validate all consumed simplified-input structures at runtime. | Open | Planned dependency-free validators, stable CLI errors, and malformed-input tests for every module. |
| M10-R5 | Re-run complete quality, benchmark, packaging, privacy, and deterministic-output gates. | Open | Planned `v2.1.1` release evidence. |

## M11: Runtime and Supply-Chain Hardening

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M11-R1 | Bound JSON, gzip, resource-count, node-count, and nesting inputs. | Open | Planned measured limits, loader enforcement, and adversarial resource tests. |
| M11-R2 | Make CI actions and development dependency resolution reproducible. | Open | Planned immutable action revisions and locked development environment. |
| M11-R3 | Exercise every documented Python minor version and validate public links and Markdown. | Open | Planned CI matrix and documentation jobs. |
| M11-R4 | Publish security, threat-model, checksum, SBOM, and build-provenance evidence. | Open | Planned security and release artifacts. |

## M12: Independent External Evaluation

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M12-R1 | Publish an evaluation protocol and independent ground-truth process before measurement. | Open | Planned protocol, schemas, and provenance rules. |
| M12-R2 | Build a sanitized, integrity-tracked independent corpus across all four modules. | Open | Planned evaluation fixtures and manifest. |
| M12-R3 | Compare overlapping behavior with an established external baseline. | Open | Planned overlap matrix and disagreement record. |
| M12-R4 | Publish classification metrics, disagreement analysis, and relevant ablations. | Open | Planned machine-readable results, runner, and evaluation report. |

## M13: Research and Application Narrative

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M13-R1 | State a bounded research question and evidence-backed contribution claims. | Open | Planned application case study and claim-to-evidence table. |
| M13-R2 | Publish methods, results, threats to validity, limitations, and future work. | Open | Planned concise technical report. |
| M13-R3 | Make personal contribution, design evolution, and difficult defects visible. | Open | Planned contribution and engineering-reflection material. |
| M13-R4 | Produce a reviewer-first README, short real-system demo, and one-page summary. | Open | Planned application presentation artifacts. |
| M13-R5 | Make public identity, version, and support information consistent. | Open | Planned metadata and documentation review. |

## M14: Final Application Release

| ID | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| M14-R1 | Reproduce the complete project and evaluation from a clean clone and wheel. | Open | Planned clean-environment release gate. |
| M14-R2 | Complete final correctness, privacy, secret, license, link, and claim reviews. | Open | Planned review records and release checklist. |
| M14-R3 | Link every post-v2.1 requirement to implementation, verification, documentation, and commit evidence. | Open | Planned completed rows in this document. |
| M14-R4 | Publish the final application release and all integrity and evaluation artifacts. | Open | Planned `v2.3.0` tag and GitHub Release. |

## Completion Rule

A roadmap milestone can move to Complete only when its open rows in this file
have implementation, verification, and documentation evidence. A successful
release or passing test suite is evidence for the rows it exercises; it does not
automatically complete unrelated roadmap scope.
