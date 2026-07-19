# Input Resource Limits

Every external JSON, gzip, credential-report, and report-artifact file crosses
the same dependency-free resource boundary before its contents are analyzed.
The limits reduce denial-of-service risk from oversized files, decompression
bombs, extreme JSON nesting, high-node documents, and unbounded resource lists.
They are safety ceilings for an offline lab, not production capacity claims.

## Default Limits

| Boundary | Limit | Applied To |
| --- | ---: | --- |
| Uncompressed JSON or credential-report file | 32 MiB | Each external file |
| Compressed gzip file | 32 MiB | Each CloudTrail `.gz` file |
| Decompressed gzip content | 64 MiB | Each CloudTrail `.gz` file |
| Aggregate decoded content | 64 MiB | Related CloudTrail or report input set |
| JSON nodes | 1,000,000 | Each document and related input set |
| JSON container nesting | 64 levels | Each parsed document |
| Primary resources or artifact records | 10,000 | One analyzer or report input set |
| Separate input files | 100 | One CloudTrail or report command |

A JSON node is an object, array, or scalar value. Object keys are covered by
the byte limit but are not counted as separate nodes. Nesting measures object
and array containers; braces or brackets inside JSON strings do not affect it.
IAM primary resources are users, groups, roles, and an optional root account.
The other module counts are buckets, security groups, and CloudTrail events.
Native IAM managed-policy records and credential-report rows are supporting
collections; each is also capped at 10,000 entries before normalization.

## Measurement Basis

The committed deterministic scale benchmark was serialized with compact JSON
and measured before these defaults were selected:

| Module | Primary Inputs | Encoded Bytes | JSON Nodes | Container Depth |
| --- | ---: | ---: | ---: | ---: |
| IAM | 5,000 | 810,062 | 40,005 | 3 |
| Storage | 5,000 | 1,850,541 | 90,003 | 4 |
| Network | 5,000 | 893,075 | 55,004 | 5 |
| CloudTrail | 10,000 | 2,885,720 | 115,003 | 4 |

The 10,000-resource ceiling preserves the largest benchmark exactly. The byte,
node, and depth limits provide substantial headroom for richer native AWS
records while remaining finite. CloudTrail receives a larger decompressed
ceiling because normal log compression can be effective; the decoded aggregate
budget prevents multiplying that allowance across many files.

## Enforcement Order

1. The reader consumes at most the configured byte limit plus one byte. It does
   not call an unbounded `read()` on an external file.
2. Gzip data is decompressed through a bounded read. Corrupt or truncated
   streams stop analysis.
3. A string-aware lexical scan rejects excessive container nesting before the
   recursive standard-library JSON decoder runs.
4. The decoded value is walked iteratively to enforce node and depth limits.
5. Schema-specific validation checks types, required fields, counts, and
   cross-field invariants.
6. Primary-resource limits are checked before per-resource normalization or
   detection whenever the source contract exposes the collection directly.

Simplified and native analyzers, compatibility CLIs, optional reachability
context, credential reports, findings, incidents, analysis summaries,
remediation plans, timelines, custom rule catalogs, benchmark manifests, and
coverage JSON paths all use the bounded reader. Related CloudTrail files share
one aggregate budget. Findings, incidents, and summaries share another budget
when a report is generated.

## Failure Contract

Limit violations raise `InputLimitError`, a `ValueError` subtype, and the CLIs
return argparse exit code `2` without producing analysis output. Simplified
inputs retain their module-specific, JSON-path-style error prefix. Messages
state the exceeded boundary and configured limit. Invalid UTF-8, malformed
JSON, corrupt gzip, conflicting records, and contract-specific truncation
markers continue to fail closed through their existing error contracts.

The fixed CLI limits are intentionally not command-line overrides. Library
tests and embedding code can construct `InputLimits` with smaller positive
values, but the supported CLI does not provide an accidental bypass.

## Residual Boundary

Accepted values are still materialized in memory because the analyzers need a
canonical environment for deterministic cross-record checks. Passing the
limits does not prove that a file is authentic, complete, current, authorized,
or safe. CloudTrail digest verification, streaming analysis, operating-system
RSS enforcement, wall-clock timeouts, and per-tenant quotas remain outside this
offline lab's scope.
