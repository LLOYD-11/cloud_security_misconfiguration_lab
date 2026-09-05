# Research Question and Evidence Claims

This document defines the research claim that the project can defend and the
evidence required for every quantitative or technical statement used in the
README, demo, case study, application summary, or interview discussion. It
prevents development results, frozen evaluation results, and broader security
claims from being blended together.

The concise [technical case study](technical-case-study.md) applies this claim
policy to the system design, method, results, failures, validity threats, and
future work.

## Bounded Research Question

> Within a frozen synthetic corpus covering 35 predefined rules over exported
> IAM, S3, EC2 security-group, and CloudTrail evidence, how accurately and
> reproducibly does version 2.1.1 of a zero-runtime-dependency offline Python
> analyzer classify predeclared rule-resource decisions, and where do its
> documented abstractions fail?

The question is deliberately tied to one candidate, one corpus, one rule
catalog, and one offline evidence model:

| Boundary | Registered Value |
| --- | --- |
| Candidate | Package `2.1.1`, revision `6d71c99914a38b6e161bc9cf56407eb1757b8c9a` |
| Rule scope | 35 fixed rules across IAM, storage, network, and CloudTrail |
| Evidence | 32 sanitized synthetic cases in 42 retained files |
| Ground truth | 176 predeclared assertions; 168 scored and 8 excluded as ambiguous |
| Classification unit | `(case_id, rule_id, resource_type, resource_id)` |
| Primary outcome | Exact finding presence or absence for each declared decision |
| Secondary outcomes | Native/simplified agreement, exact-overlap baseline agreement, severity agreement, and registered ablations |

The question does not ask whether the lab proves effective authorization,
live internet reachability, compromise, intent, causation, account-wide
coverage, or production accuracy. Those claims require evidence that the
project does not collect.

## Bounded Project Contribution

The contribution is an inspectable reference implementation that connects
four normally separate concerns: normalization of exported AWS evidence,
explainable rule evaluation, versioned cross-module security artifacts, and a
preregistered evaluation that preserves unfavorable outcomes. Its value lies
in the integration, explicit boundaries, and reproducible evidence trail.

It is not presented as a novel policy-evaluation algorithm, a comprehensive
AWS scanner, or a performance comparison proving superiority over established
tools. Individual detector ideas are grounded in published AWS and security
framework semantics; the engineering contribution is making their assumptions,
outputs, interactions, and failures reviewable end to end.

## Evidence-Based Answer

The frozen candidate achieved high classification agreement within the
registered scope, but it did not satisfy every acceptance threshold:

| Result | Frozen Value |
| --- | ---: |
| True positives | 77 |
| False positives | 2 |
| False negatives | 1 |
| True negatives | 90 |
| Precision | 0.9747 |
| Recall | 0.9872 |
| F1 | 0.9809 |
| Specificity | 0.9783 |
| Severity agreement | 77/77 matched positives |
| Registered acceptance | **Failed** |

The complete machine result is
[`evaluation/results-v1.0.json`](../evaluation/results-v1.0.json), and the
[evaluation report](evaluation-report.md) preserves the raw decisions,
intervals, acceptance checks, and disagreement analysis.

The two failed acceptance checks were storage precision (`0.8824` against a
`0.90` minimum) and two unlabelled predictions against a maximum of zero. One
genuine `IAM-005` false negative came from treating `BoolIfExists=true` as a
strict MFA requirement. Two `STO-001` outputs exposed omitted decision keys in
ambiguous storage cases and were counted as false positives under the
preregistered universe rule.

All eight native/simplified pairs produced identical decisions and severities.
The candidate also agreed with all 24 eligible exact-overlap Prowler decisions.
Sigma Core had no exact-overlap decision in the pinned release, and the network
reachability ablation had no eligible frozen case; neither absence is converted
into a favorable score.

## Post-Evaluation Boundary

The revealed `IAM-005` defect is fixed in current development and retained as
an explicit regression test. The current implementation distinguishes strict
`Bool=true` semantics from an unguarded `BoolIfExists=true`, while recognizing
`BoolIfExists=true` combined with `Null=false` as a presence-guarded condition.

This correction is development evidence, not a new holdout measurement. The
candidate revision, corpus, runner, machine result, `0.9809` F1, and failed
acceptance remain unchanged. Measuring a future candidate requires a new
preregistered protocol and unseen evidence.

## Evidence Rules

Public claims follow this evidence order:

1. Frozen machine-readable artifacts govern evaluation numbers and status.
2. Versioned contracts, architecture, and executable code govern supported
   behavior and system boundaries.
3. Commit-specific CI runs govern test, coverage, compatibility, and build
   claims for a development checkpoint.
4. Narrative documents may explain those artifacts but cannot broaden them.

Historical release evidence remains historical. Current test counts must not
be attached to candidate `2.1.1`, and the frozen evaluation score must not be
presented as a measurement of later analyzer code.

## Public Claim Register

The following register governs the project's public technical and quantitative
claims. New claims must either fit one of these rows or add a new evidence row.

| ID | Bounded Public Claim | Primary Evidence | Required Qualification |
| --- | --- | --- | --- |
| `C-01` | The runtime analyzes supplied files offline and does not authenticate to AWS or change resources. | [Architecture](architecture.md), [threat model](threat-model.md), and [project metadata](../pyproject.toml) | Collection authorization, freshness, and completeness remain outside the runtime. |
| `C-02` | The catalog contains 35 rules across IAM, S3, EC2 security groups, and CloudTrail. | [Machine-readable rule catalog](../cloud_rules/rules-v1.0.json) and [generated catalog](rule-catalog.md) | This is selected rule coverage, not complete AWS or framework coverage. |
| `C-03` | Native AWS-shaped and simplified inputs cross shared canonical analyzer boundaries. | [Architecture](architecture.md), [native input guide](native-aws-inputs.md), and versioned input schemas | Supported exports are documented subsets, not arbitrary AWS responses. |
| `C-04` | The deterministic sample produces 39 findings, 2 incidents, 36 remediation actions, and 11 timeline entries. | [Committed sample report](../reports/cloud_security_report_sample.md) and byte-comparison steps in [CI](../.github/workflows/ci.yml) | The scenario is synthetic and illustrates behavior rather than prevalence. |
| `C-05` | Development checkpoint `55bed95` passed 447 tests with 92.82% statement and 86.41% branch coverage on the measured local gate. | [CI run 51](https://github.com/LLOYD-11/cloud_security_misconfiguration_lab/actions/runs/33965567520), [coverage configuration](../pyproject.toml), and [coverage gate](../cloud_benchmarks/coverage_gate.py) | These engineering metrics are not holdout accuracy and will change as code and tests evolve. |
| `C-06` | The development benchmark passes 78 exact functional cases, 4 malformed-input rejection cases, and 8 deterministic scale profiles. | [Benchmark contract](../cloud_benchmarks/benchmark-manifest-v1.0.json) and [benchmark method](benchmarking.md) | The benchmark was developed with the analyzer and is a regression suite, not an independent accuracy estimate. |
| `C-07` | Frozen candidate `2.1.1` recorded 77 TP, 2 FP, 1 FN, 90 TN, and 0.9809 F1. | [Machine result](../evaluation/results-v1.0.json), [protocol](evaluation-protocol.md), and [evaluation report](evaluation-report.md) | Applies only to the registered synthetic corpus and candidate. |
| `C-08` | Frozen candidate `2.1.1` did not meet the preregistered acceptance target. | [Acceptance checks](evaluation-report.md#acceptance-checks) and [machine result](../evaluation/results-v1.0.json) | The failed result must accompany the F1 value. |
| `C-09` | Eight frozen native/simplified pairs had identical decisions and severities; 24 eligible exact-overlap Prowler decisions agreed. | [Registered ablations](evaluation-report.md#registered-ablations) and [baseline audit](evaluation-baselines.md) | Sigma had zero exact-overlap decisions, and no complete-tool equivalence is claimed. |
| `C-10` | The revealed `IAM-005` false negative is fixed as a post-evaluation regression. | [IAM analyzer](../iam_analyzer/analyzer.py), [regression tests](../iam_analyzer/test_analyzer.py), and [change log](../CHANGELOG.md) | It does not revise or improve the frozen evaluation score. |
| `C-11` | Findings, incidents, coverage, remediation, timelines, and reports use explicit artifact boundaries and deterministic output rules. | [Architecture](architecture.md), [data contracts](data-contracts.md), and [design decisions](design-decisions.md) | Determinism applies to documented inputs and explicit parameters, not mutable external facts. |
| `C-12` | The project exposes known evidence, policy, topology, correlation, and reporting limits. | [Known limitations](known-limitations.md) and [evaluation validity limits](evaluation-report.md#validity-and-limits) | The project is not a certification, production scanner, or substitute for analyst validation. |
| `C-13` | The project contributes an integrated, inspectable reference implementation for offline normalization, rule evaluation, shared artifacts, and preregistered evaluation. | [Architecture](architecture.md), [design decisions](design-decisions.md), and [evaluation protocol](evaluation-protocol.md) | This is an engineering and evaluation contribution, not a claim of novel security theory or scanner superiority. |
| `C-14` | The package requires Python 3.10 or later, declares no third-party runtime dependency, and is tested in CI on Python 3.10 through 3.13. | [Project metadata](../pyproject.toml), locked [CI workflow](../.github/workflows/ci.yml), and [CI run 51](https://github.com/LLOYD-11/cloud_security_misconfiguration_lab/actions/runs/33965567520) | Development and release verification use separately declared third-party tools. |
| `C-15` | Release `v2.2.1` publishes a wheel, source distribution, checksums, SPDX SBOM, and signed provenance and SBOM bundles. | [Release notes](release-v2.2.1.md), [verification guide](release-integrity.md), and [public release](https://github.com/LLOYD-11/cloud_security_misconfiguration_lab/releases/tag/v2.2.1) | Supply-chain evidence authenticates identified artifacts and workflow claims; it does not prove analyzer correctness. |

## Prohibited Overclaims

The project and application materials must not state or imply that:

- the corpus contains real customer or production AWS data;
- ground truth was independently produced by a third party;
- the lab provides complete IAM authorization or network reachability analysis;
- 0.9809 F1 estimates performance across real AWS environments;
- Prowler or Sigma is fully reproduced, replaced, or outperformed;
- a correlated incident proves compromise, intent, causation, or attribution;
- passing tests, benchmarks, or CI proves that an AWS account is secure; or
- the post-evaluation IAM correction improves the frozen holdout score.

These restrictions are part of the project's research integrity, not missing
marketing language.
