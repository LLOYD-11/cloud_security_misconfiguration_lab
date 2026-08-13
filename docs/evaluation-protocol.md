# Independent Evaluation Protocol

## Registration Status

Protocol `1.0.0` was frozen on 2026-08-12 before any M12 evaluation evidence
was shown to the candidate analyzers. The normative machine-readable record is
[`evaluation/protocol-v1.0.json`](../evaluation/protocol-v1.0.json), validated
by the
[`evaluation-protocol-v1.0`](../schemas/evaluation-protocol-v1.0.schema.json)
contract.

This registration fixed the candidate, corpus rules, labels, external
baselines, metrics, thresholds, ablations, and change policy before results
existed. The separately documented [corpus](evaluation-corpus.md) and
[external-baseline outcomes](evaluation-baselines.md) were frozen next. The
primary run is now published in the [evaluation report](evaluation-report.md);
the candidate did not meet every registered acceptance threshold.

| Frozen Item | Value |
| --- | --- |
| Candidate analyzer revision | [`6d71c99914a38b6e161bc9cf56407eb1757b8c9a`](https://github.com/LLOYD-11/cloud_security_misconfiguration_lab/commit/6d71c99914a38b6e161bc9cf56407eb1757b8c9a) |
| Installed package version | `2.1.1` |
| Intended release checkpoint | `v2.2.0` |
| Rule catalog | v1.0, 35 rules |
| Rule catalog SHA-256 | `5842caa836d7b8970ae9aef1261652cdd8f98a1c49598962de32be58c9e998a0` |
| Protocol version | `1.0.0` |

The analyzer revision predates this protocol and remains fixed for the primary
holdout run. Evaluation infrastructure may be added after registration, but a
change to analyzer behavior creates a new candidate.

## Why This Is Separate From the Benchmark

The existing [benchmark](benchmarking.md) is a development regression suite.
Its cases were built alongside the analyzers, its expected findings are visible
to maintainers, and it is intentionally optimized for complete rule and
boundary coverage. It is strong evidence of deterministic implementation but
cannot provide an unbiased estimate on unseen evidence.

M12 therefore uses a separate holdout corpus. Its evidence, labels, and case
generators cannot be copied from:

- `cloud_benchmarks/`;
- `sample_data/`;
- analyzer unit tests;
- the committed sample report; or
- prior candidate findings.

Structural AWS formats and published JSON contracts may be reused. Security
scenarios, resource identities, values, combinations, and expected decisions
must be independently authored and provenance-tracked.

## Research Questions

The primary question is whether the frozen analyzer accurately classifies
independently authored IAM, S3, EC2 security-group, and CloudTrail evidence
within its documented offline scope.

Three secondary questions measure:

1. decision equivalence between native AWS-shaped and simplified inputs;
2. agreement with pinned established tools where predicates directly overlap;
3. the effects of optional network reachability context and CloudTrail
   incident correlation.

These are bounded software-evaluation questions. They do not ask whether the
tool proves effective authorization, live internet reachability, compromise,
intent, causation, or attribution.

## Candidate Scope

The registered candidate contains 35 rules:

| Module | Rules | Input Forms |
| --- | ---: | --- |
| IAM | 15 | Native authorization and credential evidence; simplified environment |
| Storage | 6 | Native S3 evidence bundle; simplified environment |
| Network | 3 | Native EC2 security groups; simplified environment |
| CloudTrail | 11 | Native CloudTrail records; simplified events |

The exact rule IDs and catalog digest are part of the protocol. A changed rule
predicate, severity policy, normalizer, or correlation implementation is a new
candidate even if the package version has not changed.

## Independence Model

This project claims **procedural holdout independence**, not third-party or
institutional independence. The project author may know the source code and may
perform both annotation passes. The controls are designed to stop candidate
outputs from shaping evidence or labels:

1. Freeze and publish this protocol.
2. Author independent evidence and labels from retained evidence plus cited
   authoritative semantics.
3. Perform a separate verification pass without candidate output.
4. Commit the corpus manifest, labels, source references, transformations, and
   file hashes.
5. Only then run the candidate and external baselines.
6. Preserve raw decisions, exclusions, disagreements, and failed thresholds.

Each review pass records a stable reviewer ID, date, method notes, whether the
review is procedural or personnel-independent, and a mandatory declaration
that candidate output was not seen. If an external reviewer later participates,
that fact can be recorded without rewriting the original independence claim.

## Corpus Design

Every module must contain at least two cases in each class:

| Class | Purpose |
| --- | --- |
| `positive` | Evidence that directly satisfies one or more registered rule predicates |
| `hardened-negative` | Sufficient evidence showing the risky condition is absent |
| `boundary` | Exact thresholds, near misses, condition variants, or semantic edges |
| `ambiguous` | Evidence for which a forced binary label would overstate certainty |

Every rule must have at least two independently labelled positive assertions
and two negative assertions. Every module must also have at least two paired
native and simplified cases representing the same underlying evidence.

One classification unit is the tuple:

```text
(case_id, rule_id, resource_type, resource_id)
```

Corpus construction permits at most one expected finding for a decision key.
This keeps the confusion matrix finite and makes duplicate candidate findings
visible. Composite cases are allowed, but every applicable rule and resource
decision must be declared before execution.

## Provenance And Sanitization

The corpus manifest uses
[`evaluation-corpus-manifest-v1.0`](../schemas/evaluation-corpus-manifest-v1.0.schema.json).
For every input file it records:

- a repository-relative regular-file path, byte size, media type, contract, and
  SHA-256 digest;
- origin and authoritative source references with retrieval dates and
  locators;
- semantic transformations used to create the retained fixture;
- sanitization actions; and
- primary and verification review records.

Corpus files may be independently authored synthetic evidence, derived from
official documentation, or derived from public open-source material with its
origin retained. They must use fictional resources and account identifiers,
RFC 5737 or private network ranges, and no credentials, personal information,
customer data, or organization identifiers. Sanitization must not change the
predicate being labelled.

Every corpus file is declared exactly once and hashed. Symlinks, absolute
paths, parent traversal, undeclared files, duplicate paths, digest mismatch,
and candidate-output access invalidate the run.

## Ground Truth

Ground truth is derived from retained evidence and authoritative semantics, not
from majority vote among scanners.

| Label | Meaning | Primary Metrics |
| --- | --- | --- |
| `positive` | Evidence directly satisfies the registered lab-rule predicate | Included |
| `negative` | Evidence is sufficient and does not satisfy the predicate | Included |
| `ambiguous` | More than one in-scope interpretation remains reasonable | Excluded and reported |
| `unsupported` | Evidence is insufficient or the claim is outside analyzer scope | Excluded and reported |

Every assertion must cite at least one official AWS specification, API
reference, user guide, or security-control definition. A second review checks
the decision key, label, expected severity, evidence completeness, rationale,
and citations. Unresolved disagreement becomes `ambiguous`; it is never forced
into a scored class to improve coverage.

External scanner output may corroborate or challenge an annotation. It cannot
be the sole reason for the annotation because that would make baseline
agreement circular.

## External Baselines

Two established baselines are pinned before corpus execution:

| Baseline | Frozen Version | Immutable Source | Comparison Scope |
| --- | --- | --- | --- |
| [Prowler](https://docs.prowler.com/) AWS provider | [`5.38.0`](https://github.com/prowler-cloud/prowler/releases/tag/5.38.0) | [`b21ddad32c6d9a98eb819f0ccadac8a6792c2837`](https://github.com/prowler-cloud/prowler/tree/b21ddad32c6d9a98eb819f0ccadac8a6792c2837) | IAM, S3, and EC2 configuration or credential predicates with equivalent retained evidence |
| [Sigma Core](https://github.com/SigmaHQ/sigma) | [`r2026-07-01`](https://github.com/SigmaHQ/sigma/releases/tag/r2026-07-01) | [`552f3fee420ef232a8e5790c4fae591847e32347`](https://github.com/SigmaHQ/sigma/tree/552f3fee420ef232a8e5790c4fae591847e32347) | Released AWS CloudTrail selections evaluable from retained event fields |

The frozen Sigma `sigma_core.zip` asset has SHA-256 digest
`45ccbd62cbf0d7ccca6f44eaa010f86bb24f082b5411c5e22c71907e7770ee46`.

The overlap matrix uses the
[`evaluation-baseline-overlap-v1.0`](../schemas/evaluation-baseline-overlap-v1.0.schema.json)
contract and classifies every lab rule as:

- `exact`: equivalent predicate and evidence; included in agreement metrics;
- `partial`: related but broader, narrower, or otherwise different; discussed
  qualitatively; or
- `none`: no released counterpart was identified; reported without penalty.

Current AWS control documentation supplies semantic context, including the
[Security Hub CSPM control reference](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html).
Because these web pages can change, each corpus citation records its retrieval
date and locator. Prowler and Sigma source are fixed by commit.

## Classification Metrics

For a pre-labelled decision key:

| Outcome | Definition |
| --- | --- |
| True positive | Positive assertion with exactly one matching finding |
| False negative | Positive assertion without a matching finding |
| True negative | Negative assertion without a matching finding |
| False positive | Negative assertion with a finding, duplicate finding, or undeclared prediction |

An undeclared prediction is both a false positive and a corpus-completeness
defect. It is never silently removed from the denominator. Ambiguous and
unsupported assertions remain in the result artifact with an exclusion reason.

The runner will publish raw TP, FP, FN, and TN counts and calculate:

```text
precision   = TP / (TP + FP)
recall      = TP / (TP + FN)
F1          = 2 * precision * recall / (precision + recall)
specificity = TN / (TN + FP)
```

Undefined ratios are `null`, accompanied by their raw counts. Results include
overall micro, per-module, and per-rule views. Precision, recall, and
specificity use 95% Wilson score intervals. Per-rule results remain descriptive
when sample counts are small; a point estimate is not presented without its
denominator and interval.

Severity agreement is measured separately for matched positive assertions.
A correct rule decision with the wrong severity remains a true positive for
detection and a severity disagreement for risk classification.

## Frozen Acceptance Thresholds

| Check | Threshold |
| --- | ---: |
| Overall micro F1 | At least `0.90` |
| Precision for every module | At least `0.90` |
| Recall for every module | At least `0.90` |
| Critical or high false negatives | `0` |
| Native/simplified decision agreement | Exactly `1.00` |
| Unlabelled candidate predictions | `0` |

These thresholds determine whether `v2.2.0` can be described as meeting the
registered evaluation target. Results are still published when a threshold
fails. External-baseline agreement has no pass threshold because differences
in supported scope and predicate design are themselves evidence to explain.

The `0.90` classification thresholds demand consistently strong behavior while
leaving room to disclose finite-sample medium- or low-severity edge defects.
Critical and high false negatives are held to zero because those labels cover
the most consequential registered conditions. Native and simplified decisions
must agree exactly because they are documented as representations of the same
analyzer environment, not independent classifiers. Unlabelled predictions are
held to zero because they make the confusion matrix incomplete and can conceal
false positives. These are release criteria for this bounded corpus, not a
claim of universal production accuracy.

## Registered Ablations

### Native And Simplified Inputs

Paired representations must produce identical rule and resource decision sets
and severities. Provenance-only fields may differ when one representation
cannot preserve an equivalent source location.

### Network Reachability Context

Eligible network evidence is run with and without the frozen optional
reachability assessment. Context may change severity, evidence wording, and
metadata. It must not create or remove the underlying security-group rule and
resource decision.

### CloudTrail Incident Correlation

Eligible event sequences are evaluated with findings alone and with incident
correlation. Correlation may add incidents and triage context but must not alter
the underlying CloudTrail findings.

## Result Contract And Reproduction

The published runner emits
[`evaluation-results-v1.0`](../schemas/evaluation-results-v1.0.schema.json).
The result records exact protocol, corpus, overlap-matrix, candidate, and rule
catalog digests; Python and platform information; validity issues; raw
assertion decisions; unexpected predictions; confusion counts; intervals;
baseline disagreements; ablations; and every acceptance check.

No wall-clock claim is part of M12. The existing benchmark already measures
bounded resource behavior. This evaluation focuses on classification,
equivalence, and disagreement evidence.

## Change Control

Before candidate execution, a clarification may produce a new protocol version
only if the old version remains in history and no evaluation evidence has been
consumed by the candidate. After execution, any change to the candidate,
evidence, labels, matcher, baseline, metric, or threshold requires a versioned
rerun that preserves the original artifacts.

If evaluation reveals a defect and the analyzer is fixed, results on the
already visible corpus are regression results, not fresh holdout evidence. A
new holdout claim requires a second independently frozen corpus.

## Limitations

- Procedural separation is weaker than annotation by an independent research
  group; no third-party certification is claimed.
- Sanitized synthetic evidence improves safety and reproducibility but cannot
  reproduce every live AWS policy interaction, organization control, topology,
  or behavioral baseline.
- Prowler and Sigma have different data collection, scope, defaults, and rule
  goals. Only exact overlap enters agreement metrics.
- AWS web documentation is not immutable; retrieval dates and locators reduce
  but do not remove this dependency.
- Small per-rule samples produce wide intervals. Module and overall results are
  more stable, while every raw decision remains available for review.

## M12 Sequence

1. **R1, protocol:** frozen here before evaluation evidence existed.
2. **R2, corpus:** complete; 32 independently authored cases, 176 reviewed
   assertions, and 42 sanitized evidence files are frozen with exact hashes.
3. **R3, baseline:** complete; all 35 rules are classified as 5 exact, 18
   partial, or 12 without a released counterpart, and 24 exact-overlap
   baseline decisions are frozen without candidate execution. See the
   [baseline audit](evaluation-baselines.md).
4. **R4, measurement:** complete; the primary run, machine-readable results,
   disagreement analysis, ablations, and [evaluation report](evaluation-report.md)
   are published without changing the frozen method after output disclosure.

The result artifacts now enter final review before the project creates the
`v2.2.0` tag and publishes its checksum, SBOM, and signed provenance assets.
The release may publish the result, but it cannot claim that candidate `2.1.1`
met the registered evaluation target.
