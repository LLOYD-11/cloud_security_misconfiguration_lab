# Known Limitations

This project is an explainable offline lab, not a replacement for AWS IAM Access Analyzer, AWS Security Hub, or a complete policy-evaluation engine.

## Input Compatibility

- All four analyzers accept documented simplified inputs or versioned native AWS evidence.
- Runtime simplified-input validation checks consumed structure, types, selected
  cross-field invariants, and compatibility aliases. The versioned schemas
  remain the complete canonical contracts and are evaluated separately in
  development and CI; documented runtime aliases are compatibility extensions.
- Native CloudTrail input supports standard `Records` log files in JSON or gzip form, not CloudTrail Insight, aggregated-event, or digest payloads.
- External inputs fail closed at the documented
  [byte, decompression, node, depth, resource, and file-count limits](input-resource-limits.md).
  Accepted evidence is still materialized in memory; these ceilings are safety
  controls for lab datasets, not production capacity or operating-system RSS
  guarantees.
- Findings v2 preserve provenance only when the source evidence or explicit CLI
  options provide it. Versioned v1 findings migrate with `unknown` account,
  Region, and confidence plus a `null` observation time.
- `--region` and `--observed-at` are assessor-supplied context. The lab validates
  their syntax but cannot prove that they describe the input file.
- A stable finding ID identifies the same rule, resource, provenance, and source
  references. It is not a case-management ID and intentionally changes when
  those identity fields change.

## IAM Analysis

- The analyzer does not calculate effective permissions across identity policies, resource policies, service control policies, permissions boundaries, sessions, and explicit denies.
- Permissions-boundary evidence is preserved and an explicitly unrestricted boundary is reported, but identity-policy findings are not suppressed by attempting a partial boundary intersection.
- Native normalization preserves direct and group identity policies separately. An absent referenced policy, group, or boundary document is skipped with a warning rather than reconstructed.
- IAM credential reports expose active-key slots rather than access-key IDs and omit service-specific credentials; normalized key identifiers are synthetic.
- Credential reports expose only a Boolean MFA state, so the analyzer cannot distinguish hardware, passkey, and virtual MFA devices.
- Stale access-key and console-password thresholds are fixed at 90 days.
- `NotAction` and `NotResource` are flagged as broad complements rather than expanded through the complete AWS action and resource catalog. Policy variables are preserved but not resolved.
- Trust severity recognizes non-wildcard equality guards for `sts:ExternalId`, `aws:PrincipalOrgID`, and `aws:PrincipalArn`; it does not prove that external IDs are unique or that organization and ARN values are owned by the assessor.
- Some AWS actions require `Resource: "*"`; the wildcard-resource rule does not maintain the complete AWS service authorization catalog needed to suppress every legitimate exception.
- Simplified legacy user input without `password_enabled` retains the earlier console-capable assumption for backward compatibility. Native IAM input always supplies this evidence.

## Storage Analysis

- Native S3 normalization combines account-level and bucket-level Block Public Access. Simplified storage input relies on the supplied bucket values.
- Organization-level S3 Block Public Access policy evidence is not collected separately by the current bundle.
- Bucket-policy condition evaluation covers the fixed-value keys and network thresholds documented for S3 Block Public Access and conservatively requires `Null: false` for `ForAllValues` guards; it does not perform full IAM reasoning across SCPs, RCPs, VPC endpoint policies, KMS key policies, or identity policies.
- A fixed condition can be non-public while still granting unintended cross-account or network access; trust-zone review remains necessary.
- Native S3 evidence includes bucket ACLs but does not inventory every object ACL.
- S3 access point, Multi-Region Access Point, and access point policy analysis is not yet supported.
- Native S3 bundles currently cover general purpose buckets returned by `ListBuckets`, not S3 directory buckets.
- The explicit-encryption rule is a key-management posture check. S3 applies SSE-S3 to new objects even when a customer-defined bucket encryption configuration is absent.
- Versioning requirements depend on data criticality, retention requirements, and cost constraints.

## Network Analysis

- A broad security-group rule does not prove that an attached workload is internet reachable. Findings without auxiliary evidence are explicitly marked `not_assessed`.
- Optional reachability context is a trusted, point-in-time assessor attestation. The lab validates its shape and group coverage but does not parse raw AWS path-analysis output, recalculate paths, inspect a live account, or verify the stated evidence.
- A direction status is applied to all findings in its stated scope. Assessors must use `inconclusive` when attachment, address-family, protocol, port, or intermediary-path coverage is incomplete. AWS Reachability Analyzer and Network Access Analyzer currently cover IPv4 only.
- A `not_reachable` assessment lowers severity by one level but retains the permissive rule as a latent configuration risk. Network changes can invalidate the supplied conclusion.
- ENIs, public addresses, load balancers, routes, network ACLs, and firewall controls are not independently correlated by the lab.
- Native prefix-list and referenced-security-group targets are preserved with warnings but are not expanded or evaluated for public exposure.
- Native normalization accepts one owner account per snapshot. Shared-VPC or multi-owner inventories must currently be analyzed separately.
- A filtered `DescribeSecurityGroups` response does not identify itself as filtered; users must follow the documented unfiltered collection command to avoid false negatives.
- The sensitive-service catalog covers 20 documented default endpoints. Services on custom ports and uncatalogued protocols are not identified as `NET-001`.
- Broad CIDR thresholds are fixed and are not yet user configurable.

## CloudTrail Detection

- Native CloudTrail normalization accepts one recipient account per analysis. Organization-trail accounts must currently be analyzed separately.
- Identical duplicate `eventID` records are analyzed once, while conflicting
  simplified or native records using the same ID stop analysis.
- The lab does not verify CloudTrail digest signatures or prove log-file integrity.
- Change rules require both a selected high-value API name and its expected AWS
  service source, but they do not inspect policy diffs or all request
  parameters. `UpdateDetector` is the exception: it also requires explicit
  `enable: false` evidence.
- Repeated API failures can be caused by legitimate automation, probing, throttling, or configuration mistakes.
- Incident correlation uses exact finding account, normalized actor, and source values plus a bounded time window. Shared credentials, NAT, proxies, service-originated calls, unknown accounts, missing fields, and delivery gaps can split or merge activity in ways that require analyst review.
- A multi-signal incident requires distinct rules and events. It does not baseline approved administrators, working hours, expected source ranges, user agents, or change tickets.
- Incident confidence measures correlation strength, not malicious intent. Incidents remain triage leads and do not replace investigation.
- Timeline activity types are reviewer-facing descriptions of observed API activity, not MITRE ATT&CK tactics, inferred kill-chain phases, or attribution conclusions.
- A timeline entry requires a valid UTC observation time and CloudTrail event evidence reference, with legacy metadata accepted as a compatibility fallback. Missing or invalid chronology is reported as an omission, but the lab cannot reconstruct absent events or delivery gaps.
- The failure-spike rule produces one aggregate timeline entry for its detected window rather than one finding per failed API call.

## Reporting

- Severity values are primarily rule defaults and do not incorporate resource criticality. Network findings make one documented adjustment when supplied context reports `not_reachable`.
- Remediation priorities are deterministic triage bands, not breach-probability or business-impact scores. They do not include asset value, data classification, compensating controls outside the supplied evidence, ownership, effort, dependencies, change windows, or approval state.
- Configuration is linked to an incident only by an exact rule ID, `resource_type/resource_id`, and shared CloudTrail event ID. This conservative join can miss relationships that require account, session, topology, or semantic analysis.
- Timeline incident context uses the same conservative exact join. Chronological proximity alone never creates a link, and observed ordering does not prove that one action caused another.
- Equivalent remediation is grouped only when module, rule, severity, title, and action text match. The plan does not infer that different fixes can be combined into one change.
- Finding confidence measures how directly the supplied evidence supports the detector condition. It does not measure the probability that activity is malicious or replace analyst validation. Legacy v1 findings with unknown confidence fall back to catalog confidence in derived remediation and timeline views.
- `direct` control mappings indicate substantial condition alignment, not complete framework certification. `related` mappings provide security context and intentionally do not claim equivalent coverage.
- AWS Security Hub CSPM and MITRE ATT&CK references track their live public pages. CIS mappings are pinned to the AWS-published AWS Foundations Benchmark v5.0.0 crosswalk. CIS v7.0.0 is current as of this release, but control IDs are not inferred where an authoritative public crosswalk is unavailable.
- The catalog covers the 35 built-in rules. Custom findings remain report-compatible but are labeled not cataloged and receive no automatic control context.
- Analysis summaries count primary resources evaluated by each module. Skipped evidence can identify narrower unevaluated policy, credential, peer-target, reachability, or event fields without pretending that every evidence unit is a separate cloud resource.
- `complete` means that no known coverage-affecting gap was recorded for the supplied evidence. It does not prove that collection was authorized, current, account-wide, unfiltered, or free of omissions outside the supported contracts.
- A report with no findings does not prove that an AWS environment is secure.

## Benchmarking

- Benchmark profiles are synthetic and intentionally isolate documented
  conditions. They do not estimate false-positive rates in real AWS accounts or
  represent every policy, topology, workload, and user-behavior interaction.
- Runtime measurements are hardware and load dependent, so elapsed time is
  recorded but not used as a CI acceptance threshold.
- Peak-memory budgets use `tracemalloc` around analyzer execution after input
  construction. They bound traced Python allocations for the measured pass, not
  total process RSS, fixture construction cost, or operating-system memory.
- The large profiles exercise up to 10,000 inputs in memory. Passing them is not
  a claim that arbitrary production-scale exports can be processed without
  separate capacity testing.
