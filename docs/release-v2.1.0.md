# Version 2.1.0

Released: 2026-07-19

Version 2.1 completes the original M0-M9 upgrade plan. It builds on the
`v2.0.0` analyzer and reporting release with first-class provenance,
performance regression evidence, deterministic benchmark contracts, and a
reviewer-focused portfolio presentation.

## Highlights

- Findings v2 with stable IDs, confidence, account, Region, UTC observation
  time, and structured source-evidence references
- Strict migration of versioned v1 findings with unavailable provenance kept
  explicit rather than inferred
- SHA-256-verified manifests for every sanitized AWS-shaped fixture
- A monotonic CloudTrail failure-window scan with exact output-equivalence and
  structural operation-bound tests
- A machine-readable benchmark contract covering all 35 rules with 78 exact
  functional cases, four malformed-input contracts, and eight scale profiles
- Independent statement and branch coverage gates
- Python 3.10, 3.12, and 3.13 CI coverage
- A concise application-reviewer README, real report preview, five-minute demo
  guide, and requirement-to-evidence traceability

## Deterministic Evidence

The bundled sample pipeline remains stable:

| Artifact | Result |
| --- | ---: |
| Findings | 39 |
| Built-in rules | 35 |
| Analysis summaries | 4 |
| Correlated incidents | 2 |
| Remediation actions | 36 |
| Timeline entries | 11 |
| Timeline omissions | 0 |

Run:

```bash
python3 -m cloud_security_lab demo --report-date 2026-06-30
```

The generated report must match
[`reports/cloud_security_report_sample.md`](../reports/cloud_security_report_sample.md)
byte-for-byte.

## Verification

The release gate records:

- 300 unit, regression, integration, CLI, schema, compatibility, and benchmark
  tests
- 4,477 of 4,703 statements covered (95.19%)
- 1,694 of 1,900 branches covered (89.16%)
- 78 of 78 exact functional benchmark cases
- Four of four malformed native inputs rejected with exact error contracts
- Eight of eight deterministic scale profiles passing from 100 to 10,000 inputs
- Ruff linting and strict production mypy checks
- Byte-for-byte report and rule-catalog regeneration
- Native IAM, S3, EC2, and CloudTrail pipeline checks
- Wheel and source-distribution builds
- A clean-environment wheel installation, deterministic demo, and packaged
  benchmark run

Elapsed benchmark time remains observational rather than gated. Exact outputs,
bounded amplification, repeated-run equality, structural operation bounds, and
calibrated memory ceilings provide stable regression evidence across shared CI
runners.

## Compatibility

- Python 3.10 or later is required.
- The runtime has no third-party dependencies.
- Existing module scripts remain supported alongside the unified CLI.
- New analyzer exports use findings v2.
- Versioned v1 finding files remain readable through explicit migration.
- Unversioned finding lists remain rejected.
- Existing rule-catalog, incident, remediation, timeline, and benchmark
  contract versions remain unchanged.

## Evidence Boundary

Version 2.1 remains an offline analysis lab. It does not authenticate to AWS,
change resources, calculate complete effective IAM permissions, independently
prove network reachability, verify CloudTrail log integrity, establish
malicious intent, or estimate production false-positive rates.

See [Known limitations](known-limitations.md),
[Benchmarking and resilience](benchmarking.md), and
[Upgrade traceability](traceability.md) for the complete interpretation boundary
and acceptance evidence.

## Completion History

The final upgrade sequence is preserved as reviewable commits:

- `524d45e`: restore the M0-M9 roadmap and traceability
- `df7b774`: add first-class finding provenance and fixture manifests
- `4f2bea9`: optimize CloudTrail failure-window detection
- `f9efca2`: add deterministic benchmark and coverage gates
- `956e97f`: complete portfolio presentation and repository metadata

The annotated `v2.1.0` tag identifies the verified completion release.
