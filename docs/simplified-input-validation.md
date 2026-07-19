# Simplified-Input Runtime Validation

Every simplified IAM, storage, network, and CloudTrail JSON file crosses the
same dependency-free validation boundary before analysis. The unified CLI and
all four compatibility entry points use the module loaders that enforce this
boundary.

## Failure Contract

The validator stops at the first invalid value and raises a stable,
path-oriented error:

```text
Invalid simplified network input at $.security_groups[0].inbound_rules[0].cidr: expected a valid IPv4 or IPv6 CIDR.
```

The CLIs convert this error into exit code `2` without writing findings,
incidents, summaries, or normalized output. Direct loader callers receive
`SimplifiedInputError`, a `ValueError` subtype.

## Validated Evidence

The runtime boundary verifies the structures and primitive values consumed by
each analyzer:

| Module | Runtime checks |
| --- | --- |
| IAM | Account, identity, credential, policy, statement, trust, principal, condition, and permissions-boundary shapes |
| Storage | Bucket controls, ACL grants, policy statements, encryption, versioning, Region, and Object Ownership |
| Network | Security groups, rules, targets, CIDRs, ports, peer context, tags, and optional reachability assessments |
| CloudTrail | Event containers, RFC 3339 times, service and event names, identities, source values, request/response objects, and optional account context |

The network validator also rejects inverted port ranges and invalid CIDRs.
Timestamp-bearing inputs require a known RFC 3339 offset and are canonicalized
to UTC `Z` before analysis, including separately supplied network reachability
context. The RFC 3339 unknown-local-offset form `-00:00` is rejected rather than
misrepresented as UTC. Required account IDs use the 12-digit AWS form.

## Compatibility

The canonical schemas use normalized lowercase policy fields. The IAM analyzer
also preserves its documented support for unambiguous AWS-style statement keys
such as `Effect`, `Action`, and `Resource`, including `document.Statement`
wrappers. The storage compatibility path accepts an unambiguous bucket-policy
`Statement`. Network rules preserve the analyzer's `cidr_ip` and `cidr_ipv6`
compatibility aliases. Defining multiple forms for the same field is rejected
instead of silently selecting one. IAM statements also reject simultaneous
positive and negative forms such as `Action` with `NotAction`.

## Relationship To JSON Schema

Runtime validation is focused on analyzer-consumed evidence and selected
cross-field invariants. It is not a custom implementation of the complete JSON
Schema standard. CI independently evaluates the published Draft 2020-12
schemas with the optional development dependency, validates committed samples
and generated canonical environments, and then passes native-normalizer output
through this runtime boundary as a round-trip check.

Byte, resource-count, decompression, node-count, nesting-depth, and input-file
ceilings are enforced by the separate shared
[input resource boundary](input-resource-limits.md) before or alongside this
contract validation. Structural validity does not establish evidence freshness,
provenance, completeness, authorization, or security.
