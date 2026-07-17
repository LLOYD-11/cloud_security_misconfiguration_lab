# Known Limitations

This project is an explainable offline lab, not a replacement for AWS IAM Access Analyzer, AWS Security Hub, or a complete policy-evaluation engine.

## Input Compatibility

- All four analyzers accept documented simplified inputs or versioned native AWS evidence.
- Native CloudTrail input supports standard `Records` log files in JSON or gzip form, not CloudTrail Insight, aggregated-event, or digest payloads.
- Evidence is loaded into memory and is intended for small lab datasets.

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

- A broad security-group rule does not prove that an attached workload is internet reachable.
- ENIs, public addresses, load balancers, routes, network ACLs, and firewall controls are not yet correlated.
- Native prefix-list and referenced-security-group targets are preserved with warnings but are not expanded or evaluated for public exposure.
- Native normalization accepts one owner account per snapshot. Shared-VPC or multi-owner inventories must currently be analyzed separately.
- A filtered `DescribeSecurityGroups` response does not identify itself as filtered; users must follow the documented unfiltered collection command to avoid false negatives.
- Broad CIDR thresholds are fixed and are not yet user configurable.

## CloudTrail Detection

- Native CloudTrail normalization accepts one recipient account per analysis. Organization-trail accounts must currently be analyzed separately.
- Identical duplicate `eventID` records are removed with a warning, while conflicting records using the same ID stop analysis.
- The lab does not verify CloudTrail digest signatures or prove log-file integrity.
- Change rules identify selected high-value API names but do not inspect policy diffs or all request parameters.
- Repeated API failures can be caused by legitimate automation, probing, throttling, or configuration mistakes.
- Related events are not yet correlated into a single incident or attack timeline.

## Reporting

- Severity values are rule defaults and do not yet incorporate resource criticality or confidence.
- Module coverage currently counts findings rather than all evaluated and skipped resources.
- A report with no findings does not prove that an AWS environment is secure.
