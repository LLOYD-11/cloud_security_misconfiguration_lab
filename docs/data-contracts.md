# Data Contracts

The repository publishes versioned JSON Schema contracts for its simplified offline inputs, supported native exports, findings, incidents, analysis summaries, rules, remediation plans, and attack timelines.

| Contract | Schema |
| --- | --- |
| AWS CloudTrail log file | [`aws-cloudtrail-records-v1.0.schema.json`](../schemas/aws-cloudtrail-records-v1.0.schema.json) |
| AWS IAM authorization details snapshot | [`aws-iam-authorization-details-v1.0.schema.json`](../schemas/aws-iam-authorization-details-v1.0.schema.json) |
| AWS EC2 security group snapshot | [`aws-ec2-describe-security-groups-v1.0.schema.json`](../schemas/aws-ec2-describe-security-groups-v1.0.schema.json) |
| AWS S3 security evidence bundle | [`aws-s3-evidence-bundle-v1.0.schema.json`](../schemas/aws-s3-evidence-bundle-v1.0.schema.json) |
| Sanitized AWS fixture manifest | [`aws-fixture-manifest-v1.0.schema.json`](../schemas/aws-fixture-manifest-v1.0.schema.json) |
| IAM environment | [`iam-environment-v1.0.schema.json`](../schemas/iam-environment-v1.0.schema.json) |
| Storage environment | [`storage-environment-v1.0.schema.json`](../schemas/storage-environment-v1.0.schema.json) |
| Network environment | [`network-environment-v1.0.schema.json`](../schemas/network-environment-v1.0.schema.json) |
| Optional network reachability context | [`network-reachability-context-v1.0.schema.json`](../schemas/network-reachability-context-v1.0.schema.json) |
| CloudTrail-style events | [`cloudtrail-events-v1.0.schema.json`](../schemas/cloudtrail-events-v1.0.schema.json) |
| Analysis summary | [`analysis-summary-v1.0.schema.json`](../schemas/analysis-summary-v1.0.schema.json) |
| Detection rule catalog | [`rule-catalog-v1.0.schema.json`](../schemas/rule-catalog-v1.0.schema.json) |
| Shared findings file (current) | [`findings-v2.0.schema.json`](../schemas/findings-v2.0.schema.json) |
| Shared findings file (legacy read compatibility) | [`findings-v1.0.schema.json`](../schemas/findings-v1.0.schema.json) |
| Correlated incidents file | [`incidents-v1.0.schema.json`](../schemas/incidents-v1.0.schema.json) |
| Prioritized remediation plan | [`remediation-plan-v1.0.schema.json`](../schemas/remediation-plan-v1.0.schema.json) |
| Attack timeline | [`attack-timeline-v1.0.schema.json`](../schemas/attack-timeline-v1.0.schema.json) |
| Benchmark manifest | [`benchmark-manifest-v1.0.schema.json`](../schemas/benchmark-manifest-v1.0.schema.json) |
| Benchmark results | [`benchmark-results-v1.0.schema.json`](../schemas/benchmark-results-v1.0.schema.json) |

The schemas use JSON Schema Draft 2020-12. Contract tests validate every committed sample, the built-in rule catalog, the benchmark manifest, and analyzer-generated findings, incident, analysis-summary, remediation-plan, attack-timeline, and benchmark-result files against these schemas.

The environment contracts describe the lab's simplified analyzer models. The native IAM contract describes the fields consumed from a non-truncated AWS `GetAccountAuthorizationDetails` snapshot; the accompanying credential report follows AWS's CSV contract and is validated by required headers and values in Python. Its normalized contract preserves root credentials, console-password usage, group membership, direct policy origin, and permissions-boundary context without treating a boundary as a grant. The S3 bundle contract groups multiple native account and per-bucket responses, including Object Ownership, without flattening collection errors into configuration values. Its normalized contract preserves positive and negative policy elements plus condition context so public-access evaluation does not reduce a policy to its principal alone. The EC2 contract represents a complete direct `DescribeSecurityGroups` response; its adapter flattens permission targets while retaining CIDR, prefix-list, and security-group peer context in the network environment. The optional reachability contract carries separately obtained, direction-specific path conclusions with scope, method, timestamp, evidence, and related resource IDs; it is an assessor attestation rather than a raw AWS API response. The CloudTrail contracts describe the simplified environment and supported native `Records` entries. Both paths analyze identical duplicate IDs once and reject conflicting records before detection; native JSON or gzip files are merged only after record validation. All normalizers convert native evidence into versioned analyzer environments, keeping the detection interface stable.

Runtime analyzers use only the Python standard library and perform lightweight top-level validation. Full JSON Schema validation is a development and CI gate supplied by the optional `dev` dependencies.

New finding exports use schema v2.0. Each finding carries a deterministic
`FND-` ID, evidence-to-rule confidence, account, Region, optional UTC
observation time, and one or more structured evidence references. The stable ID
is a SHA-256-derived identity over rule, module, account, Region, observation
time, resource, and sorted evidence references. Descriptive text, severity,
confidence, references, and metadata do not change identity.
Equivalent UTC timestamps ending in `Z` or `+00:00` are canonicalized to `Z`
before identity is calculated.

The loader accepts versioned v1 and v2 files. V1 records are migrated in memory
with `unknown` account, Region, and confidence, a `null` observation time, and a
legacy evidence reference; the migration never infers unavailable provenance.
All new writes use v2.0. Unversioned lists and unsupported versions remain
rejected.

The shared findings and incident loaders also verify that each declared count
equals the number of objects in its corresponding list. V2 finding IDs are
recomputed and checked so a changed identity field cannot retain a stale ID.
The incident model additionally verifies UTC time ordering and that
`event_count` equals the number of unique event IDs. The analysis-summary model
verifies resource-count arithmetic, deterministic ordering, input and module
values, and consistency between coverage status and coverage-affecting evidence
gaps.

The remediation-plan model verifies deterministic priority ordering, stable and
unique action IDs, complete one-time accounting of source findings in
configuration work, and one response action for every source incident.
Artifact text, including remediation rationale, remains format-neutral; only
the Markdown report renderer introduces presentation syntax.

The attack-timeline model verifies UTC chronological ordering, stable and unique
entry IDs, valid activity classifications, exact source accounting across
entries and omissions, and explicit incident links. The timeline is derived
from CloudTrail findings rather than raw events so each entry retains detector
evidence, impact, severity, and finding confidence. Versioned v1 findings with
unknown confidence fall back to the built-in catalog; custom unknown rules use
`not-assessed`.

The AWS fixture manifest records the operation or assessment shape, local
contract, authoritative shape references, synthetic origin, account and Region
scope, observation range, sanitization, expected rule coverage, and SHA-256 for
every bundled AWS-shaped file. Contract tests require the manifest inventory to
exactly match the files under `sample_data/aws/` and verify every digest.

The benchmark manifest records exact positive and boundary expectations for
every built-in rule, module-level hardened and malformed evidence, false-positive
rationale, unsupported evidence, a rule-to-case matrix, separate coverage
thresholds, and deterministic scale budgets. The benchmark-result contract
records functional and malformed case outcomes plus scale counts, amplification,
elapsed time, traced peak memory, and repeated-run determinism. See
[Benchmarking and resilience](benchmarking.md).

The canonical [`rules-v1.0.json`](../cloud_rules/rules-v1.0.json) catalog adds
cross-field checks for unique and deterministically ordered rule IDs, module
prefixes, default and allowed severities, confidence values, known frameworks,
qualified mapping relationships, and HTTPS source links. Built-in analyzers
validate each emitted rule, module, and severity against this catalog. Reports
apply the same validation to known rules while retaining explicit compatibility
for third-party custom rule IDs. These relationships are enforced in Python
because JSON Schema does not express them directly.
