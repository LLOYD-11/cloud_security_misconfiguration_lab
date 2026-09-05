# Version 2.2.0

Released: 2026-09-05

Version 2.2 closes the M11-M12 runtime-hardening and independent-evaluation
checkpoint. It keeps the offline AWS-only analysis scope while adding bounded
input handling, reproducible development dependencies, pinned CI, signed
release evidence, and an immutable pre-registered holdout result.

## Highlights

- Evidence-based byte, decompression, resource, node, depth, and aggregate
  limits across simplified and native inputs
- Hash-locked development dependencies and immutable GitHub Actions revisions
- Strict Markdown, internal-link, and bounded external-link quality gates
- A public security policy and threat model
- An installed-wheel SPDX 2.3 SBOM, deterministic `SHA256SUMS`, signed build
  provenance, and a signed SBOM predicate
- A frozen 32-case, 176-assertion evaluation corpus covering all 35 rules
- A complete Prowler/Sigma overlap audit with 24 exact-overlap baseline decisions
- Immutable machine-readable results, confidence intervals, disagreement
  analysis, registered ablations, and a release-safe isolated replay command

## Runtime Hardening

All external JSON, gzip, credential-report, related-file, and report-artifact
paths cross shared fail-closed resource boundaries. Encoded and decompressed
bytes, JSON depth and nodes, primary resources, artifact records, and aggregate
multi-file work are bounded before unbounded analysis begins. Malformed,
truncated, oversized, deeply nested, or ambiguous evidence returns stable
user-facing errors rather than partial findings.

The runtime remains dependency-free. Development and release tools install from
one universal SHA-256-locked environment, and CI exercises Python 3.10, 3.11,
3.12, and 3.13.

## Independent Evaluation

The protocol froze candidate `2.1.1` at commit `6d71c99`, the rule catalog,
corpus process, labels, Prowler and Sigma baselines, metrics, thresholds,
ablations, and change policy before candidate execution. The primary result is
published unchanged:

| Measure | Result |
| --- | ---: |
| Cases | 32 |
| Assertions | 176 total; 168 scored; 8 ambiguous and excluded |
| Confusion matrix | 77 TP, 2 FP, 1 FN, 90 TN |
| Precision | 0.9747 |
| Recall | 0.9872 |
| F1 | 0.9809 |
| Severity agreement | 77/77 matched positives |
| Exact-overlap Prowler agreement | 24/24 |
| Native/simplified decision agreement | 8/8 |
| Registered acceptance | **Not met**; 10 of 12 checks passed |

Storage precision was `0.8824` against a `0.90` threshold, and two predictions
were unlabelled against a threshold of zero. The disagreement analysis identifies
one genuine medium-severity `IAM-005` false negative and two `STO-001` corpus
decision-universe omissions. The frozen network-reachability ablation had zero
eligible cases and remains disclosed as non-estimable. This release does not
describe candidate `2.1.1` as meeting the registered target.

## Frozen Candidate Replay

Package version `2.2.0` must not replace the implementation measured as
candidate `2.1.1`. From a clone with full Git history, run:

```bash
.venv/bin/python -m tools.evaluation_replay
```

The command creates a temporary local checkout at commit `6d71c99`, overlays
only frozen evaluation artifacts, and invokes the byte-unchanged runner there.
It requires no network access and verifies all raw decisions, metrics,
acceptance checks, object values, and canonical result bytes. The original
primary result and runner remain unchanged.

## Release Integrity

The tag-triggered workflow repeats the complete quality gate, builds the wheel
and source distribution, inventories an isolated wheel installation with pinned
Syft, and produces six public asset files:

- Wheel
- Source distribution
- SPDX 2.3 SBOM
- `SHA256SUMS`
- Signed SLSA build-provenance bundle
- Signed SPDX SBOM-attestation bundle

The low-privilege build job verifies the checksum and signer identity before a
separate release-authority job re-verifies transferred evidence and publishes
the GitHub Release.

## Verification

The release-candidate gate records:

- 443 unit, regression, integration, CLI, schema, compatibility, evaluation,
  supply-chain, and benchmark tests
- 6,861 of 7,392 statements covered (92.82%)
- 2,509 of 2,906 branches covered (86.34%)
- 78 of 78 exact functional benchmark cases
- Four of four malformed native inputs rejected with exact error contracts
- Eight of eight deterministic scale profiles passing from 100 to 10,000 inputs
- Ruff, strict production mypy, Markdown, internal-link, and external-link gates
- Byte-exact sample report, rule catalog, and frozen evaluation reproduction
- Native IAM, S3, EC2, and CloudTrail pipeline checks
- Wheel and source-distribution builds plus clean-wheel demo and benchmark runs
- A clean privacy and secret-pattern review

## Compatibility

- Python 3.10 or later is required.
- The runtime has no third-party dependencies.
- Unified and legacy module commands remain supported.
- Finding, analysis, incident, remediation, timeline, rule-catalog, benchmark,
  and evaluation contracts remain versioned and backward compatible.
- Analyzer rule semantics are unchanged after the frozen candidate revision;
  post-evaluation rule corrections belong to a later candidate and regression
  record.

## Evidence Boundary

Version 2.2 remains an offline analysis and research lab. It does not collect
live AWS evidence, change resources, calculate complete IAM authorization,
prove network reachability, verify CloudTrail digest chains, infer malicious
intent, or estimate universal production accuracy. The evaluation corpus is
sanitized and synthetic, and both output-blind ground-truth passes were
performed by the project author rather than an independent third party.

See [Independent evaluation results](evaluation-report.md),
[Release integrity](release-integrity.md), [Threat model](threat-model.md), and
[Known limitations](known-limitations.md) for the complete interpretation and
trust boundaries.

## Completion History

- `e7dedd2`: bound untrusted input resources
- `ff94404`: lock the development supply chain
- `b171e65`: validate the Python matrix and public documentation
- `6d71c99`: publish release-integrity controls and freeze the candidate
- `d537cfd`: preregister the independent evaluation
- `a405124`: freeze the evaluation corpus and ground truth
- `e707995`: freeze external-baseline outcomes
- `d316a1c`: freeze the primary measurement runner
- `5067d05`: publish the immutable primary result

## Publication Outcome

The annotated `v2.2.0` tag froze this M11-M12 checkpoint. Its release workflow
passed the full quality gate, generated and verified the checksum, SBOM, build-
provenance, and SBOM-attestation evidence, and reverified the transferred
assets. The final publication command then failed safely because the isolated
release-authority job had no Git worktree and did not identify the repository
explicitly. No GitHub Release was created and the tag was not moved or deleted.
The failed run remains visible as [Release workflow #4](https://github.com/LLOYD-11/cloud_security_misconfiguration_lab/actions/runs/33952155558).

Version `2.2.1` carries this evidence forward unchanged and corrects only that
repository-selection defect. See the [version 2.2.1 release notes](release-v2.2.1.md).
