# Independent Evaluation Baselines

## Freeze Status

M12-R3 freezes a complete rule-level overlap matrix and external-baseline
outcomes before the candidate is executed on the holdout corpus. The normative
artifacts are:

- [`baseline-overlap-v1.0.json`](../evaluation/baseline-overlap-v1.0.json),
  validated by the preregistered
  [`evaluation-baseline-overlap-v1.0`](../schemas/evaluation-baseline-overlap-v1.0.schema.json)
  contract; and
- [`baseline-outcomes-v1.0.json`](../evaluation/baseline-outcomes-v1.0.json),
  validated by the supplemental
  [`evaluation-baseline-outcomes-v1.0`](../schemas/evaluation-baseline-outcomes-v1.0.schema.json)
  contract.

The outcomes contain no candidate prediction, agreement rate, accuracy claim,
or acceptance result. Those remain separate M12-R4 fields in the
[primary result](evaluation-report.md). External scanner output is
corroborating evidence and never defines corpus ground truth.

## Frozen Sources

| Baseline | Version | Immutable Source | Release Evidence |
| --- | --- | --- | --- |
| Prowler AWS provider | `5.38.0` | [`b21ddad32c6d9a98eb819f0ccadac8a6792c2837`](https://github.com/prowler-cloud/prowler/tree/b21ddad32c6d9a98eb819f0ccadac8a6792c2837) | Exact replay predicates retain upstream file paths and SHA-256 digests. |
| Sigma Core | `r2026-07-01` | [`552f3fee420ef232a8e5790c4fae591847e32347`](https://github.com/SigmaHQ/sigma/tree/552f3fee420ef232a8e5790c4fae591847e32347) | `sigma_core.zip` SHA-256 `45ccbd62cbf0d7ccca6f44eaa010f86bb24f082b5411c5e22c71907e7770ee46`; all 12 released AWS CloudTrail rule paths and file digests are retained. |

The Sigma repository commit contains additional test or experimental AWS
rules that are absent from the pinned Core release asset. They are not treated
as released baseline coverage. This distinction is why a repository rule that
looks related can still produce a `none` mapping here.

## Comparison Method

Each of the 35 lab rules has exactly one row against the baseline assigned to
its module. Rows use the preregistered relationship policy:

- `exact`: equivalent rule-level predicate and retained evidence; eligible for
  later agreement measurement;
- `partial`: related coverage with a broader, narrower, or otherwise different
  predicate; qualitative only; or
- `none`: no released counterpart; no baseline penalty.

The audit was deliberately conservative. Shared topics such as public S3
access, wildcard IAM access, or security-control changes are not enough for an
`exact` classification when thresholds, fields, decision units, guardrails, or
event sets differ.

Prowler normally collects live provider state and Sigma defines portable log
selections. The retained corpus is an offline set of canonical and AWS-shaped
fixtures, not a live AWS account or a SIEM backend. M12-R3 therefore does not
claim that either complete upstream CLI was executed. For exact overlap only,
[`evaluation_baselines.py`](../tools/evaluation_baselines.py) independently
replays the audited upstream predicate over equivalent retained fields. It
does not import candidate analyzers, execute the frozen candidate, or use
assertion labels and expected severities in prediction logic.

## Overlap Results

| Baseline Scope | Exact | Partial | None | Total |
| --- | ---: | ---: | ---: | ---: |
| Prowler: IAM, storage, network | 5 | 15 | 4 | 24 |
| Sigma Core: CloudTrail | 0 | 3 | 8 | 11 |
| **All lab rules** | **5** | **18** | **12** | **35** |

The five exact Prowler mappings are:

| Lab Rule | Prowler Check | Eligible Decisions |
| --- | --- | ---: |
| `IAM-006` | `iam_user_mfa_enabled_console_access` | 4 |
| `IAM-007` | `iam_rotate_access_key_90_days` | 4 |
| `IAM-013` | `iam_no_root_access_key` | 4 |
| `STO-004` | `s3_bucket_default_encryption` | 6 |
| `STO-005` | `s3_bucket_object_versioning` | 6 |

The replay produces 24 frozen decisions: 11 positive and 13 negative. The
remaining 152 corpus assertions are preserved as explicit exclusions: 88 due
to partial overlap, 56 due to no released counterpart, and eight because their
ambiguous cases were already marked baseline-ineligible. Nothing is silently
dropped.

Sigma has no exact rule-level mapping in the pinned Core asset. Three released
rules are partial counterparts for `CLD-005`, `CLD-008`, and `CLD-010`; each
adds or omits material event conditions. Reporting zero eligible Sigma
decisions is the measured scope result, not a failed comparison.

## Reproduction And Tamper Checks

Verify the frozen corpus, matrix, replay, schemas, hashes, counts, and complete
assertion partition:

```bash
.venv/bin/python -m tools.evaluation_baselines
```

Regenerate both deterministic artifacts from the reviewed mapping and replay
implementation, then verify them:

```bash
.venv/bin/python -m tools.evaluation_baselines --write
```

The verifier fails closed when the corpus no longer verifies, a rule is
missing or reordered, a relationship or rationale changes, a baseline
prediction changes, a Sigma release-inventory digest changes, an assertion is
lost or duplicated, an ineligible assertion becomes a decision, or a committed
artifact differs from deterministic replay.

## Interpretation Limits

- Source-audited predicate replay is narrower than running Prowler against a
  live AWS account or compiling Sigma for a production SIEM backend.
- Exact overlap is a semantic classification retained under project-author
  accountability with material AI assistance, not personnel-independent review
  or third-party certification. See the
  [authorship disclosure](contribution-and-reflection.md).
- Prowler and Sigma can collect or infer context absent from the retained
  fixtures. Those differences are documented as partial or unsupported scope.
- The 24 decisions are frozen baseline outputs, not an estimate of candidate
  quality. The later primary result reports 24/24 candidate agreement within
  this exact-overlap subset; it does not extend that rate to partial or missing
  counterparts.
