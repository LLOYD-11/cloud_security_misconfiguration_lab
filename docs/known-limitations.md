# Known Limitations

This project is an explainable offline lab, not a replacement for AWS IAM Access Analyzer, AWS Security Hub, or a complete policy-evaluation engine.

## Input Compatibility

- The current analyzers consume documented simplified JSON models rather than unmodified AWS CLI or API responses.
- CloudTrail input currently expects an `events` list and does not yet read `Records` payloads or gzip archives.
- Evidence is loaded into memory and is intended for small lab datasets.

## IAM Analysis

- The analyzer does not calculate effective permissions across identity policies, resource policies, service control policies, permissions boundaries, sessions, and explicit denies.
- `NotAction`, `NotResource`, policy variables, and the full AWS action catalog are not yet modeled.
- External trust conditions such as `sts:ExternalId` and `aws:PrincipalOrgID` do not yet lower finding confidence or severity.
- Some AWS actions require `Resource: "*"`; the current wildcard-resource rule does not maintain a service action catalog for those exceptions.

## Storage Analysis

- Public-principal detection does not yet evaluate policy conditions, access points, account-level Block Public Access, or Object Ownership.
- The explicit-encryption rule is a key-management posture check. S3 applies SSE-S3 to new objects even when a customer-defined bucket encryption configuration is absent.
- Versioning requirements depend on data criticality, retention requirements, and cost constraints.

## Network Analysis

- A broad security-group rule does not prove that an attached workload is internet reachable.
- ENIs, public addresses, load balancers, routes, network ACLs, and firewall controls are not yet correlated.
- Broad CIDR thresholds are fixed and are not yet user configurable.

## CloudTrail Detection

- Change rules identify selected high-value API names but do not inspect policy diffs or all request parameters.
- Repeated API failures can be caused by legitimate automation, probing, throttling, or configuration mistakes.
- Related events are not yet correlated into a single incident or attack timeline.

## Reporting

- Severity values are rule defaults and do not yet incorporate resource criticality or confidence.
- Module coverage currently counts findings rather than all evaluated and skipped resources.
- A report with no findings does not prove that an AWS environment is secure.
