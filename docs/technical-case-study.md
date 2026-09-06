# Technical Case Study: Evidence-Bounded Offline AWS Security Analysis

## Executive Summary

Cloud security assessment tools often depend on live credentials, mutable
provider state, and opaque scanner output. This project explores a narrower
question: whether exported AWS evidence can be analyzed offline through an
explainable, deterministic pipeline whose claims remain tied to inspectable
artifacts.

The resulting Python system normalizes documented IAM, S3, EC2 security-group,
and CloudTrail exports, applies 35 selected rules, and emits versioned findings,
coverage summaries, incidents, remediation actions, timelines, and a combined
report. The runtime has no third-party dependencies and never authenticates to
AWS or changes cloud resources.

Evaluation was separated from the development benchmark. Candidate `2.1.1`
was frozen before a 32-case, 176-assertion synthetic corpus was constructed and
reviewed without candidate output. The primary run recorded 77 true positives,
2 false positives, 1 false negative, and 90 true negatives, giving micro F1
`0.9809`. It nevertheless failed two preregistered acceptance checks: storage
precision was `0.8824`, below `0.90`, and two candidate predictions had no
predeclared decision keys.

The most important result is therefore not the F1 value alone. The evaluation
exposed both an analyzer defect and a corpus-review defect, preserved them in
the frozen result, and converted the revealed analyzer boundary into a later
regression test without rewriting the original score.

## Research Question

The complete scope and public claim policy are defined in the
[research question and evidence register](research-question.md). The bounded
question is:

> Within a frozen synthetic corpus covering 35 predefined rules over exported
> IAM, S3, EC2 security-group, and CloudTrail evidence, how accurately and
> reproducibly does version 2.1.1 of a zero-runtime-dependency offline Python
> analyzer classify predeclared rule-resource decisions, and where do its
> documented abstractions fail?

This is a software-evaluation question. It is not a claim about production
breach detection, complete AWS authorization, live reachability, attacker
intent, or the security of an account.

## System Under Study

The system uses a staged evidence pipeline rather than coupling AWS parsing,
detection, and presentation:

| Stage | Responsibility | Evidence Boundary |
| --- | --- | --- |
| Input | Read simplified fixtures or documented native AWS-shaped exports within fixed resource ceilings. | Supplied files may still be incomplete, stale, or unauthorized. |
| Normalization | Validate native response structure and translate it into one canonical environment per module. | Adapters cover documented subsets rather than arbitrary AWS responses. |
| Detection | Apply module-owned rule predicates and emit shared `Finding` objects. | Findings report selected conditions, not effective account security. |
| Derivation | Build coverage summaries, incidents, remediation priorities, and chronological views. | Correlation and priority remain explainable triage aids, not causal or probabilistic claims. |
| Reporting | Validate artifact versions and relationships before deterministic Markdown rendering. | Presentation cannot add evidence absent from source artifacts. |
| Evaluation | Replay a frozen candidate against output-blind labels and audited baseline predicates. | Results apply only to the registered candidate and corpus. |

The detailed dependency and trust boundaries are published in the
[architecture](architecture.md), while the main tradeoffs are recorded as
[design decisions](design-decisions.md). The system intentionally favors
offline reproducibility, conservative joins, shared contracts, and visible
evidence gaps over live collection or broad inference.

## Method

### Candidate And Rule Freeze

The [evaluation protocol](evaluation-protocol.md) fixed package `2.1.1`, commit
`6d71c99914a38b6e161bc9cf56407eb1757b8c9a`, the 35-rule catalog digest,
classification unit, metrics, thresholds, baselines, ablations, and change
policy before evaluation evidence was executed. A later predicate, normalizer,
severity, or correlation change therefore represents a different candidate.

The classification unit was the exact tuple:

```text
(case_id, rule_id, resource_type, resource_id)
```

Exactly one matching finding was required for a positive assertion. Missing
positive findings were false negatives. Findings on negative assertions,
duplicate findings, and predictions without a predeclared decision key were
false positives. Ambiguous and unsupported assertions remained visible but
were excluded from classification metrics.

### Development Assurance Versus Holdout Evidence

The project already had a deterministic development benchmark with positive,
boundary, hardened-negative, malformed-input, and scale cases. Those expected
outputs were visible during implementation, so the benchmark was treated as a
regression contract rather than an accuracy estimate.

The M12 holdout reused structural contracts but did not reuse sample scenarios,
benchmark expectations, analyzer tests, sample-report findings, or candidate
output. This separation matters because a system cannot provide an unbiased
measurement by testing only cases that shaped its implementation.

### Corpus And Ground Truth

The frozen [corpus](evaluation-corpus.md) contains 32 synthetic cases in 42
hashed files. Each of the four modules has two positive, two hardened-negative,
two boundary, and two ambiguous cases. Across all cases, 78 positive and 90
negative assertions were scored; 8 ambiguous assertions were retained but
excluded.

Ground truth came from retained evidence and cited AWS semantics, not scanner
majority vote. Two output-blind review passes checked each declared decision
key, label, severity, rationale, evidence boundary, and citation before
candidate execution. Both passes remained under project-author accountability,
and AI assistants materially supported artifact preparation. The study
therefore claims procedural separation rather than personnel or third-party
independence. The [contribution disclosure](contribution-and-reflection.md)
defines that assistance boundary.

Every corpus path, size, contract, media type, transformation, sanitization
action, and SHA-256 digest is recorded. Candidate-independent verification
rejects changed evidence, undeclared files, lost declared assertions, output
exposure, unsafe paths, and broken native/simplified pair structure.

### External Baselines

All 35 rules were audited against pinned Prowler AWS `5.38.0` and Sigma Core
`r2026-07-01` sources before candidate execution. A rule entered agreement
metrics only when its predicate and retained evidence were classified as exact
overlap. Partial and absent counterparts remained qualitative scope evidence.

Five Prowler predicates had exact overlap, producing 24 eligible decisions.
Sigma Core had three partial relationships but no exact released counterpart.
The project replayed only the audited exact upstream predicates over retained
fields; it did not run either complete scanner against a live account. The
[baseline audit](evaluation-baselines.md) preserves source commits, hashes,
mapping rationale, decisions, and exclusions.

### Metrics, Thresholds, And Ablations

The runner published raw confusion counts, precision, recall, F1, specificity,
per-module and per-rule results, 95% Wilson intervals, and separate severity
agreement. Acceptance required all of the following:

- overall micro F1 of at least `0.90`;
- precision and recall of at least `0.90` for every module;
- zero critical or high false negatives;
- exact native/simplified decision agreement; and
- zero unlabelled candidate predictions.

Three preregistered ablations examined native/simplified equivalence, optional
network reachability context, and CloudTrail incident correlation. A missing
eligible experiment had to be reported as not estimable rather than repaired
after results were visible.

## Results

### Classification

Primary run `EVAL-RUN-2026-08-13-PRIMARY` executed at
`2026-08-13T01:26:34Z` from a clean worktree using Python `3.12.6` on macOS
arm64. The machine result retains the complete environment record and artifact
digests.

| Scope | TP | FP | FN | TN | Precision | Recall | F1 | Specificity |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Overall micro | 77 | 2 | 1 | 90 | 0.9747 | 0.9872 | 0.9809 | 0.9783 |
| IAM | 30 | 0 | 1 | 30 | 1.0000 | 0.9677 | 0.9836 | 1.0000 |
| Storage | 15 | 2 | 0 | 21 | 0.8824 | 1.0000 | 0.9375 | 0.9130 |
| Network | 8 | 0 | 0 | 10 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| CloudTrail | 24 | 0 | 0 | 29 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

The 168 declared positive and negative assertions are joined by two undeclared
predictions that the protocol counts as additional false positives, so the
overall confusion matrix contains 170 classification outcomes. Full Wilson
intervals and raw decisions remain in the [evaluation report](evaluation-report.md)
and [machine result](../evaluation/results-v1.0.json).

Severity matched for all 77 matched positive assertions. Thirty-three of 35
rules had perfect retained-corpus classification. `IAM-005` had F1 `0.8000`
because of one false negative, while `STO-001` had F1 `0.7500` after the two
undeclared predictions were counted as false positives. Small rule-level
denominators prevent broader per-rule accuracy claims.

### Acceptance And Secondary Outcomes

Ten of twelve acceptance checks passed. The result remained failed because
storage precision missed its threshold and the candidate emitted two
unlabelled predictions.

| Secondary Check | Eligible Evidence | Result | Interpretation |
| --- | ---: | ---: | --- |
| Native/simplified equivalence | 8 pairs | 1.0000 agreement | Decisions and severities matched for all pairs. |
| Prowler exact-overlap agreement | 24 decisions | 24/24 | Applies only to five audited exact predicates. |
| Sigma exact-overlap agreement | 0 decisions | `null` | No exact released counterpart was eligible. |
| Network reachability ablation | 0 cases | Not estimable | The frozen corpus contained no eligible context artifact. |
| CloudTrail correlation ablation | 8 cases | 1.0000 finding agreement; 4 incidents added | Correlation added triage objects without changing findings. |

## Failure Analysis

### Analyzer Defect: IAM-005

Case `EVAL-IAM-006` granted a sensitive action under
`BoolIfExists: {"aws:MultiFactorAuthPresent": "true"}`. AWS documents that
[`IfExists`](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html)
can match when the key is absent. Candidate `2.1.1` searched for the MFA key and
a `true` value but ignored the condition operator, so it incorrectly suppressed
the finding.

The root cause was an overly broad abstraction: a helper named as though it
recognized an MFA requirement actually recognized only an MFA-related key and
value. The later correction requires strict `Bool=true` values or the logically
equivalent `BoolIfExists=true` plus `Null=false` presence guard. Mixed true and
false policy values are rejected as non-strict because AWS evaluates
[multiple values for one condition key as alternatives and multiple operators together](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html).

The exposed case is now a development regression test alongside additional
operator-interaction boundaries. The frozen candidate, runner, result, and
failed acceptance remain unchanged.

### Corpus Defect: STO-001 Decision Universe

Cases `EVAL-STO-007` and `EVAL-STO-008` were designed around ambiguous public
ACL interpretation, but both also contained `ignore_public_acls: false`. That
field independently satisfied the registered `STO-001` predicate. The
output-blind review declared only the ambiguous ACL decision and omitted the
applicable Block Public Access decision keys.

The analyzer outputs are therefore not evidence that the `STO-001` condition
was implemented incorrectly. They are evidence that the supposedly complete
decision universe was incomplete. The preregistered rule treated each
undeclared output as a false positive and a corpus-completeness defect, making
the gap visible instead of silently discarding it.

Any future corpus erratum must be versioned and reported as a sensitivity
analysis. It cannot replace the original labels or retroactively turn the
primary run into a passing result.

### Missing Experiment: Network Context

The protocol registered a reachability-context ablation, but no eligible
context artifact survived into the frozen corpus. The runner reported zero
eligible cases and no estimate. Adding a favorable example after candidate
output was visible would have violated the study design.

This failure is methodological rather than a zero effect. A future experiment
needs new preregistered cases that hold security-group rules constant while
varying bounded reachability evidence.

## Threats To Validity

| Threat | Mitigation | Residual Risk |
| --- | --- | --- |
| Construct validity | Exact rule-resource decisions, separate severity agreement, and qualified control mappings limit what each score represents. | Rule matches are proxies for selected evidence conditions, not effective AWS security or malicious intent. |
| Internal validity | Candidate identity, protocol, labels, evidence hashes, baseline logic, and thresholds were frozen before execution. | Both label reviews and overlap classifications remained under project-author accountability and used material AI assistance; personnel independence is not claimed. |
| Decision-universe completeness | Every declared key was frozen and undeclared outputs were penalized. | Two storage predictions proved that manual output-blind review still missed applicable keys. |
| External validity | All four modules, every rule, positive, negative, boundary, ambiguous, and native/simplified cases were represented. | Thirty-two synthetic cases cannot estimate behavior across real organizations, policies, topology, workloads, or event prevalence. |
| Conclusion validity | Raw denominators, micro and module metrics, Wilson intervals, severity checks, and failed thresholds were published. | Two positive and two negative assertions per rule leave wide rule-level uncertainty; micro F1 can hide weak individual rules. |
| Baseline validity | Only source-audited exact predicates entered agreement metrics; partial and absent mappings were disclosed. | Predicate replay is narrower than executing Prowler or Sigma end to end in their normal environments. |
| Ablation validity | Eligibility and allowed effects were fixed before execution. | The network experiment had no eligible case and supports no conclusion. |
| Reproducibility | Canonical JSON, exact digests, full raw decisions, locked tools, and isolated candidate replay are public. | AWS web semantics and hosted execution environments can change despite recorded retrieval dates and pinned executable inputs. |

## Operational Limitations

The study's evaluation boundary sits inside the broader product limits:

- IAM rules do not calculate effective permissions across identity policies,
  resource policies, service control policies, permissions boundaries,
  sessions, and explicit denies.
- S3 analysis does not cover every object ACL, access point, Multi-Region
  Access Point, organization policy, or interacting identity and KMS policy.
- Security-group rules do not independently establish internet reachability;
  optional context remains a trusted point-in-time assessor statement.
- CloudTrail processing does not verify digest signatures, reconstruct missing
  events, baseline approved behavior, or infer attacker intent.
- Severity and remediation priority omit business impact, asset value, data
  classification, ownership, compensating controls, effort, and change windows.
- Synthetic evidence and deterministic outputs support inspection and
  reproducibility, not claims about real-world prevalence or capacity.

The full boundary inventory is maintained in [Known limitations](known-limitations.md)
and the [threat model](threat-model.md).

## Current Development State

After the holdout result was disclosed, development checkpoint
[`55bed95`](https://github.com/LLOYD-11/cloud_security_misconfiguration_lab/commit/55bed9536cdb099e5ea6a8a38ca68162a7c58d9d)
corrected the `IAM-005` operator semantics and added regression boundaries.
Its local reference gate passed 447 tests with 92.82% statement and 86.41%
branch coverage, 78/78 exact benchmark cases, 4/4 malformed-input rejections,
and 8/8 scale profiles. [CI run 51](https://github.com/LLOYD-11/cloud_security_misconfiguration_lab/actions/runs/33965567520)
passed the same gates across Python 3.10 through 3.13.

These are software-assurance results for later code. They do not update the
classification table above, which remains a measurement of candidate `2.1.1`.

## Future Work

| Priority | Work | Evidence Required Before Claiming Success |
| --- | --- | --- |
| 1 | Evaluate a future candidate on an unseen corpus under a new protocol. | New candidate digest, preregistration, untouched cases, frozen labels, raw decisions, and preservation of the v1 result. |
| 2 | Add personnel-independent annotation where feasible. | Named review roles, conflict process, output-blind declarations, and agreement records without rewriting original labels. |
| 3 | Publish a versioned storage decision-universe erratum. | Added `STO-001` keys, rationale, changed-metric sensitivity analysis, and an explicit statement that the primary result remains authoritative. |
| 4 | Run the missing network-context experiment. | Preregistered paired cases with constant rules, eligible reachability evidence, expected invariant decisions, and allowed severity changes. |
| 5 | Add a bounded real-system demonstration. | Authorized disposable AWS environment, documented collection commands, cost and credential controls, sanitized exports, and teardown evidence. |
| 6 | Expand semantic scope only behind explicit contracts. | New rules or a proven policy engine for effective IAM interactions, S3 access points, richer network paths, or signed CloudTrail evidence, each with new tests and evaluation cases. |

The [real-system demo protocol](real-system-demo.md), minimal deployment
template, and safety assertions now prepare priority 5. Actual execution,
sanitized AWS evidence, and teardown verification remain pending and are not
claimed by this case study.

The order matters. Fixing known cases strengthens regression safety, but only a
new unseen corpus can support a new generalization claim.

## Reproduction

From a clean clone with the locked development environment:

```bash
.venv/bin/python -m tools.evaluation_corpus
.venv/bin/python -m tools.evaluation_baselines
.venv/bin/python -m tools.evaluation_replay
.venv/bin/python -m cloud_benchmarks.runner
.venv/bin/python -m unittest discover
```

The replay creates an isolated local checkout of candidate `2.1.1`, overlays
only frozen evaluation artifacts, and compares the reconstructed result with
the committed canonical JSON. A successful replay authenticates the published
failed result; it does not convert acceptance to pass.

## Conclusion

Within its frozen synthetic scope, candidate `2.1.1` classified most declared
rule-resource decisions correctly and reproduced equivalent native and
simplified decisions. The evidence does not support a claim of production
accuracy or complete cloud-security analysis, and the candidate did not meet
its own preregistered acceptance target.

The strongest contribution is the reviewable chain from exported evidence to
bounded claims: explicit contracts, deterministic artifacts, visible coverage
gaps, output-blind evaluation, preserved failures, and post-evaluation change
control. That chain makes both the successful behavior and the limitations
available for independent inspection.
