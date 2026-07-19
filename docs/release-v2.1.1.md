# Version 2.1.1

Released: 2026-07-19

Version 2.1.1 closes the verified M10 boundary defects found during the
post-v2.1 correctness review. It keeps the offline AWS-only scope and existing
rule catalog while making event matching, duplicate handling, report rendering,
and simplified-input failures explicit and reproducible.

## Correctness Fixes

- CloudTrail change detections now require both the expected AWS service source
  and API name, preventing same-name events from another service from firing a
  rule.
- Simplified CloudTrail evidence rejects conflicting records with the same
  `eventID` in either input order while still analyzing identical duplicates
  once.
- Markdown reports escape artifact-derived prose, table cells, code spans,
  headings, references, and paths according to their rendering context.
  Model-valid text can no longer create report sections or table structure.
- Remediation rationale remains format-neutral data; the report renderer alone
  owns Markdown presentation.

## Input Boundary

- Every simplified IAM, storage, network, and CloudTrail file now crosses one
  dependency-free, path-aware runtime validator before analysis.
- Unified and compatibility CLIs return exit code `2` with the same
  module-specific error contract for malformed nested evidence.
- IAM policy elements, storage controls, network targets, CIDRs, port ranges,
  optional reachability context, CloudTrail identities, and request/response
  containers are validated before detection.
- Unambiguous documented compatibility forms remain accepted, including
  AWS-style policy statements and legacy network CIDR fields. Conflicting forms
  fail closed.
- Offset-aware evidence times are canonicalized to UTC `Z`; invalid,
  unrepresentable, or unknown-local-offset times are rejected.

## Deterministic Evidence

The bundled sample output is unchanged:

| Artifact | Result |
| --- | ---: |
| Findings | 39 |
| Built-in rules | 35 |
| Analysis summaries | 4 |
| Correlated incidents | 2 |
| Remediation actions | 36 |
| Timeline entries | 11 |
| Timeline omissions | 0 |

The generated report and rule-catalog documentation match their committed
references byte-for-byte.

## Verification

The release gate records:

- 328 unit, regression, integration, CLI, schema, compatibility, and benchmark
  tests
- 4,979 of 5,229 statements covered (95.22%)
- 1,903 of 2,146 branches covered (88.68%)
- 78 of 78 exact functional benchmark cases
- Four of four malformed native benchmark inputs rejected
- Eight of eight deterministic scale profiles passing from 100 to 10,000 inputs
- Ruff linting and strict production mypy checks across 43 source files
- Native IAM, S3, EC2, and CloudTrail pipeline checks
- Wheel and source-distribution builds with the validator packaged
- A repository-external wheel installation, deterministic demo, packaged
  benchmark run, and installed validator error-contract probe
- A clean privacy and secret-pattern scan with generated and local artifacts
  remaining untracked

## Compatibility

- Python 3.10 or later is required.
- The runtime still has no third-party dependencies.
- Existing unified and module compatibility commands remain supported.
- Finding, incident, analysis-summary, remediation, timeline, rule-catalog, and
  benchmark contract versions are unchanged.
- Valid v2.1.0 simplified and native sample evidence remains accepted.
- Structurally malformed or semantically ambiguous simplified evidence that was
  previously tolerated now fails before analysis.

## Evidence Boundary

This release does not add live AWS collection, cloud credentials, resource
changes, full IAM authorization evaluation, independent network-path proof,
CloudTrail digest verification, malicious-intent attribution, or production
accuracy estimates. Resource and nesting limits, reproducible dependency
resolution, independent evaluation, and supply-chain artifacts remain planned
for M11-M14.

See [Simplified-input runtime validation](simplified-input-validation.md),
[Report-integrity boundary](report-integrity.md),
[Known limitations](known-limitations.md), and
[Upgrade traceability](traceability.md).

## Completion History

- `00f4e64`: define the post-v2.1 upgrade route
- `c1b433f`: scope CloudTrail rules to AWS event sources
- `2a61ada`: reject conflicting CloudTrail event IDs
- `3839df8`: preserve Markdown report structure
- `55905a7`: validate simplified analyzer inputs
- `cc2405e`: preserve the published IAM v1.0 schema contract while retaining
  stricter runtime invariants

The annotated `v2.1.1` tag identifies the verified M10 boundary release.
