# Benchmarking and Resilience

The project publishes a deterministic benchmark contract for all 35 built-in
rules. It is designed to make analyzer behavior, decision boundaries,
fault-tolerance expectations, and scale limits reviewable without connecting to
an AWS account.

## Machine-Readable Contract

The committed
[`benchmark-manifest-v1.0.json`](../cloud_benchmarks/benchmark-manifest-v1.0.json)
contains 78 functional cases:

| Classification | Cases | Purpose |
| --- | ---: | --- |
| Positive | 35 | Exercise each built-in rule with minimal deterministic evidence. |
| Boundary | 35 | Prove a near miss or exact threshold does not trigger the mapped rule. |
| Hardened negative | 4 | Prove one safe environment per module produces no findings. |
| Native malformed | 4 | Prove one incomplete or malformed native input per module fails closed. |

The `rule_coverage` matrix links every rule to one case in all four classes.
Module-level negative and malformed cases are intentionally shared by rules in
the same analyzer because they validate the analyzer-wide safe baseline and
native evidence boundary. Positive and boundary cases remain rule-specific.

Expected output is stored as exact counted signatures over `rule_id`, severity,
resource type, and resource ID. Companion findings are explicit. This prevents
a test from passing merely because the target rule appears somewhere in a
larger result.

Every case records:

- why the supplied evidence can still require analyst validation;
- which evidence is intentionally unsupported;
- the exact expected finding signatures, or the exact exception type and
  message for malformed evidence.

The manifest and generated result use versioned Draft 2020-12 schemas:

- [`benchmark-manifest-v1.0.schema.json`](../schemas/benchmark-manifest-v1.0.schema.json)
- [`benchmark-results-v1.0.schema.json`](../schemas/benchmark-results-v1.0.schema.json)

## Golden Snapshot Maintenance

Run the committed snapshot directly:

```bash
.venv/bin/python -m cloud_benchmarks.runner
```

This writes `reports/generated/benchmark_results.json`. To intentionally
regenerate expected signatures after a reviewed analyzer change:

```bash
.venv/bin/python -m cloud_benchmarks.manifest_builder \
  --output cloud_benchmarks/benchmark-manifest-v1.0.json
```

The builder is a review tool, not an acceptance oracle. CI never regenerates
the manifest. It executes the committed expectations, and a contract test
separately proves that the builder remains deterministic. Any snapshot diff must
therefore be reviewed as a behavior change before it is committed.

## Scale Profiles and Budgets

Each analyzer has a deterministic small and large corpus. Exactly 10% of inputs
produce one selected rule, allowing exact input, finding, per-rule, and
amplification checks.

| Profile | Small inputs | Large inputs | Expected rule |
| --- | ---: | ---: | --- |
| IAM | 100 | 5,000 | `IAM-006` |
| Storage | 100 | 5,000 | `STO-005` |
| Network | 100 | 5,000 | `NET-001` |
| CloudTrail | 200 | 10,000 | `CLD-006` |

CI requires:

- 100% of functional cases to match exact signatures;
- 100% of malformed cases to reject with the exact error contract;
- exact input, finding, and per-rule counts for every scale profile;
- finding amplification no greater than 0.10 findings per input;
- identical `Finding` objects from a repeated analysis;
- peak traced analyzer allocations no greater than 16 MiB for small profiles
  and 64 MiB for large profiles.

Wall-clock duration is measured and reported but is not an acceptance gate.
Shared CI runners vary in CPU scheduling and load, so a seconds threshold would
create noise without proving algorithmic stability. Determinism, exact counts,
bounded amplification, structural detector tests, and generously calibrated
memory ceilings provide stable regression signals instead.

## Reference Measurement

The following non-gating reference run was recorded on 2026-07-18 using Python
3.12.6 on Darwin arm64. Timing covers the first analyzer pass. Peak memory uses
`tracemalloc` after the deterministic input has been constructed and therefore
measures traced analyzer allocations rather than total process RSS.

| Case | Inputs | Findings | Seconds | Peak traced bytes |
| --- | ---: | ---: | ---: | ---: |
| `iam-small` | 100 | 10 | 0.002303 | 15,755 |
| `iam-large` | 5,000 | 500 | 0.113913 | 613,288 |
| `storage-small` | 100 | 10 | 0.004037 | 20,947 |
| `storage-large` | 5,000 | 500 | 0.191230 | 898,176 |
| `network-small` | 100 | 10 | 0.006432 | 33,975 |
| `network-large` | 5,000 | 500 | 0.303753 | 1,484,324 |
| `cloudtrail-small` | 200 | 20 | 0.010275 | 126,122 |
| `cloudtrail-large` | 10,000 | 1,000 | 0.523583 | 4,923,803 |

These values are reproducibility evidence, not throughput guarantees. Different
Python builds, hardware, operating systems, and concurrent load will produce
different elapsed times.

## Coverage Evidence

The 2026-07-18 release-gate run executed 300 tests and measured the production
packages, including `cloud_benchmarks`:

| Metric | Covered | Total | Result | Minimum |
| --- | ---: | ---: | ---: | ---: |
| Statements | 4,477 | 4,703 | 95.19% | 90.00% |
| Branches | 1,694 | 1,900 | 89.16% | 85.00% |

`coverage.py` also reports a combined display percentage, but the acceptance
gate deliberately computes statements and branches independently from
`coverage.json`. Meeting one metric cannot hide a failure in the other.

## Interpretation Limits

The corpora are synthetic and selected to exercise documented rules and
boundaries. They do not estimate production false-positive rates, represent all
AWS policy interactions, or prove live reachability, malicious intent, or
account-wide evidence completeness. The per-case rationale and unsupported
evidence fields exist so benchmark success is not mistaken for those claims.
