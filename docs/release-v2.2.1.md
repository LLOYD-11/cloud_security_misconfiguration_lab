# Version 2.2.1

Released: 2026-09-05

Version 2.2.1 publishes the unchanged M11-M12 runtime-hardening and independent-
evaluation checkpoint with a corrected release-authority command. The
`v2.2.0` workflow completed all quality, build, checksum, SBOM, provenance, and
attestation checks, then safely stopped before publication because its isolated
publisher was not inside a Git worktree. This patch makes repository selection
explicit without weakening that isolation boundary.

## Release Correction

- `gh release create` now receives `--repo "$GITHUB_REPOSITORY"`.
- The release-authority job still has no source checkout and no Python runtime.
- Build and publish permissions remain split across separate jobs.
- Checksums and both signed attestation bundles are reverified after artifact
  transfer and before the GitHub Release is created.
- A supply-chain regression test prevents removal of the explicit repository
  binding.

## Version 2.2 Evidence

The patch changes no analyzer rules, input contracts, benchmark cases,
evaluation labels, frozen candidate code, frozen runner, or primary results.
It carries the complete [version 2.2.0 checkpoint](release-v2.2.0.md), including:

- bounded simplified and native input handling;
- a SHA-256-locked development environment and immutable Actions revisions;
- strict documentation and link gates;
- a public security policy and threat model;
- wheel and source distributions, SPDX 2.3 SBOM, `SHA256SUMS`, signed build
  provenance, and a signed SBOM predicate; and
- a preregistered 32-case, 176-assertion independent evaluation covering all 35
  rules.

## Frozen Evaluation Result

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

The primary result remains unchanged and candidly records the `IAM-005` false
negative, two `STO-001` decision-universe omissions, and a non-estimable network-
reachability ablation. Package version `2.2.1` is not substituted for the frozen
candidate `2.1.1`; full-history clones reproduce the result through the isolated
candidate replay command:

```bash
.venv/bin/python -m tools.evaluation_replay
```

## Verified Release Gate

The release candidate is required to pass:

- 443 tests;
- 92.82% statement and 86.34% branch coverage;
- 78 of 78 exact functional benchmark cases;
- four of four malformed native-input contracts;
- eight deterministic scale profiles from 100 to 10,000 inputs;
- Ruff, strict production mypy, Markdown, and internal/external link checks;
- byte-exact sample-report, rule-catalog, and frozen-result reproduction; and
- independent wheel, source-distribution, checksum, SBOM, provenance, and clean-
  installation verification.

See [Independent evaluation results](evaluation-report.md),
[Release integrity](release-integrity.md), [Threat model](threat-model.md), and
[Known limitations](known-limitations.md) for the full evidence and its limits.
