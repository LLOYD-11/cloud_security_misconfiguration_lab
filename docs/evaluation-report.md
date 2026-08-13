# Independent Evaluation Results

## Result Status

The frozen `2.1.1` candidate did **not** meet every preregistered acceptance
threshold. Its overall micro F1 was `0.9809`, but storage precision was
`0.8824` against a `0.90` threshold and the candidate produced two unlabelled
predictions against a threshold of zero. Publishing this failed acceptance is
part of the registered method; labels, evidence, matching logic, and thresholds
were not changed after candidate output was revealed.

| Item | Frozen Value |
| --- | --- |
| Evaluation ID | `EVAL-RUN-2026-08-13-PRIMARY` |
| Executed at | `2026-08-13T01:26:34Z` |
| Candidate revision | `6d71c99914a38b6e161bc9cf56407eb1757b8c9a` |
| Candidate package | `2.1.1` |
| Pre-execution runner freeze | `d316a1c696b404f741fe121fab309ec738019582` |
| Protocol | `1.0.0` |
| Corpus | 32 cases, 176 assertions, 42 retained files |
| Environment | Python `3.12.6`, macOS arm64, clean Git worktree |
| Machine result | [`results-v1.0.json`](../evaluation/results-v1.0.json) |
| Result SHA-256 | `5bce3ded5a87bd6e7ef35db432defea54f78908ad6cf656ec0e00cb9cc7c6e34` |

The primary run scored 168 positive and negative assertions. Eight ambiguous
assertions remain visible but are excluded from classification metrics. An
undeclared candidate prediction is an additional false positive under the
registered universe rule, so the overall confusion counts include 170 scored
classification outcomes.

## Classification Results

Intervals are two-sided Wilson 95% confidence intervals. Values are rounded to
four decimal places here; the machine result retains full precision and every
raw assertion decision.

| Scope | TP | FP | FN | TN | Precision (95% CI) | Recall (95% CI) | F1 | Specificity (95% CI) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Overall micro | 77 | 2 | 1 | 90 | 0.9747 (0.9123-0.9930) | 0.9872 (0.9309-0.9977) | 0.9809 | 0.9783 (0.9242-0.9940) |
| IAM | 30 | 0 | 1 | 30 | 1.0000 (0.8865-1.0000) | 0.9677 (0.8381-0.9943) | 0.9836 | 1.0000 (0.8865-1.0000) |
| Storage | 15 | 2 | 0 | 21 | 0.8824 (0.6566-0.9671) | 1.0000 (0.7961-1.0000) | 0.9375 | 0.9130 (0.7320-0.9758) |
| Network | 8 | 0 | 0 | 10 | 1.0000 (0.6756-1.0000) | 1.0000 (0.6756-1.0000) | 1.0000 | 1.0000 (0.7225-1.0000) |
| CloudTrail | 24 | 0 | 0 | 29 | 1.0000 (0.8620-1.0000) | 1.0000 (0.8620-1.0000) | 1.0000 | 1.0000 (0.8830-1.0000) |

Severity matched exactly for all 77 matched positive assertions. The single
false negative has no observed severity to compare, and severity is not scored
for undeclared predictions. Of 35 rules, 33 had perfect retained-corpus
classification. The two exceptions were:

| Rule | TP | FP | FN | TN | Precision | Recall | F1 | Specificity |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `IAM-005` | 2 | 0 | 1 | 2 | 1.0000 | 0.6667 | 0.8000 | 1.0000 |
| `STO-001` | 3 | 2 | 0 | 3 | 0.6000 | 1.0000 | 0.7500 | 0.6000 |

Small per-rule samples produce wide intervals. These rule rows identify exact
boundaries to investigate; they are not estimates of production prevalence.

## Disagreement Analysis

### IAM-005 False Negative

`EVAL-IAM-006` contains a sensitive user permission guarded by
`BoolIfExists: {"aws:MultiFactorAuthPresent": "true"}`. AWS documents that an
[`IfExists` condition](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html)
can still match when the request context key is absent, so the condition does
not strictly require an MFA-present value on every request path. The frozen
label is therefore positive for `IAM-005`.

The candidate's [IAM condition helper](../iam_analyzer/analyzer.py) accepts any
condition operator when it finds the MFA key and a `true` value. It does not
distinguish strict `Bool` from `BoolIfExists`, so the candidate suppressed the
finding. This is one genuine medium-severity analyzer false negative. It did
not violate the zero critical/high false-negative threshold.

A future candidate should evaluate the operator as well as the key and value,
then add this case to its development regression suite. Because the holdout is
now visible, that repaired run must be reported as a regression result rather
than a fresh holdout result.

### STO-001 Unlabelled Predictions

`EVAL-STO-007` and `EVAL-STO-008` were authored to preserve ambiguity in
`STO-002`: each has a broad ACL grant but omits Object Ownership evidence, so
the ACL may be enabled or disabled. Both cases also retain
`ignore_public_acls: false`. That independently satisfies the `STO-001`
predicate for an incomplete bucket-level Block Public Access configuration.

The frozen manifest declares only the ambiguous `STO-002` decision in those
two cases. The two `STO-001` findings are therefore undeclared predictions.
Under the preregistered universe rule, each is counted as a false positive and
also disclosed as a corpus-completeness defect. This is not evidence that the
`STO-001` detector condition itself is wrong; it is evidence that the output-
blind corpus review missed an applicable decision key.

The original corpus and result remain immutable. A future corpus erratum may
add the missing decisions in a new version, but it must preserve this primary
result and report how the correction changes metrics.

No candidate finding matched a frozen negative assertion, and no duplicate
candidate findings occurred. These three records are the complete set of
classification disagreements and unexpected predictions.

## Acceptance Checks

Ten of twelve preregistered checks passed. The overall target did not pass
because acceptance requires every check, not an average across checks.

| Check | Observed | Threshold | Result |
| --- | ---: | ---: | --- |
| Overall micro F1 | 0.9809 | at least 0.90 | Pass |
| IAM precision | 1.0000 | at least 0.90 | Pass |
| IAM recall | 0.9677 | at least 0.90 | Pass |
| Storage precision | 0.8824 | at least 0.90 | **Fail** |
| Storage recall | 1.0000 | at least 0.90 | Pass |
| Network precision | 1.0000 | at least 0.90 | Pass |
| Network recall | 1.0000 | at least 0.90 | Pass |
| CloudTrail precision | 1.0000 | at least 0.90 | Pass |
| CloudTrail recall | 1.0000 | at least 0.90 | Pass |
| Critical/high false negatives | 0 | at most 0 | Pass |
| Native/simplified decision agreement | 1.0000 | exactly 1.00 | Pass |
| Unlabelled predictions | 2 | at most 0 | **Fail** |

The project therefore does not claim that candidate `2.1.1` met the registered
M12 acceptance target.

## Registered Ablations

| Experiment | Eligible Cases | Decision Agreement | Severity Changes | Incident Change | Invariant |
| --- | ---: | ---: | ---: | ---: | --- |
| Native/simplified equivalence | 8 | 1.0000 | 0 | 0 | Pass |
| Network reachability context | 0 | not estimable | 0 | 0 | Not estimable |
| CloudTrail incident correlation | 8 | 1.0000 | 0 | +4 | Pass |

All eight frozen native/simplified pairs produced identical rule/resource
decision sets and severities. CloudTrail correlation added four incidents
without creating, removing, or changing a finding.

The frozen R2 corpus retained no network reachability-context artifact, so the
registered network experiment had no eligible case. Adding evidence after
seeing candidate output would violate the freeze. The result remains valid for
its classification questions, but this missing experiment is a disclosed,
non-gating validity limitation and must be covered by a future preregistered
corpus.

## External Baseline Agreement

The candidate agreed on all 24 exact-overlap Prowler decisions. Sigma Core had
zero exact-overlap decisions in the pinned release, so its agreement rate is
`null`, not zero or one. The result does not convert partial or unsupported
mappings into penalties and does not claim complete Prowler or Sigma
equivalence.

| Baseline | Eligible Decisions | Agreements | Disagreements | Agreement Rate |
| --- | ---: | ---: | ---: | ---: |
| Prowler AWS `5.38.0` | 24 | 24 | 0 | 1.0000 |
| Sigma Core `r2026-07-01` | 0 | 0 | 0 | null |

## Validity And Limits

- Ground truth used two output-blind review passes, but both were performed by
  the project author. Procedural separation is not personnel independence.
- The corpus is sanitized and synthetic. It tests frozen predicates, not live
  organization policy, topology, data collection, or event prevalence.
- Two positive and two negative assertions per rule provide breadth but wide
  per-rule uncertainty. Module and overall estimates are more stable.
- The two undeclared storage predictions show that the asserted decision
  universe was not complete in every ambiguous case.
- The network reachability ablation was not estimable because R2 froze no
  eligible context artifact.
- Prowler comparison is source-audited predicate replay over retained evidence,
  not a live end-to-end scanner run. Sigma had no exact eligible mapping.
- AWS documentation is mutable; the corpus records retrieval dates and
  locators but cannot make upstream semantics immutable.

These limits constrain the claim to this candidate, corpus, protocol, and
offline scope. The result is not third-party certification or evidence of
universal production accuracy.

## Reproduction

From a clean clone with full Git history and the locked development environment:

```bash
.venv/bin/python -m tools.evaluation_corpus
.venv/bin/python -m tools.evaluation_baselines
.venv/bin/python -m tools.evaluation_runner
```

The final command re-executes all registered candidate paths, validates the
result contract and internal count invariants, and compares the generated
object and canonical JSON bytes with the committed artifact. It exits
successfully when the published result is authentic and reproducible even
though the recorded acceptance value is `false`. The original `--write` path
now refuses to overwrite the frozen primary result.
