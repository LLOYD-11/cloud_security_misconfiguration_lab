# Attack Timeline

The report pipeline converts eligible CloudTrail findings into a deterministic
chronology. The timeline helps a reviewer understand what was observed and in
what order without relabeling audit evidence as a proven attack.

The Markdown report includes the chronology directly. The `report` command can
also write a machine-readable artifact:

```bash
python3 -m cloud_security_lab report \
  --findings reports/generated/cloudtrail_findings.json \
  --incidents reports/generated/cloudtrail_incidents.json \
  --timeline-output reports/generated/attack_timeline.json \
  --output reports/generated/cloud_security_report.md
```

The JSON output follows
[`attack-timeline-v1.0.schema.json`](../schemas/attack-timeline-v1.0.schema.json).

## Evidence Eligibility

Only findings whose `module` is `cloudtrail` are timeline candidates. Each
candidate must contain:

- A v2 UTC `observed_at`, or legacy metadata with a valid UTC `event_time` or
  `first_seen` and optional `last_seen`
- At least one v2 `cloudtrail-event` evidence reference, or legacy metadata with
  an `event_id` or comma-separated `event_ids` value

Structured v2 provenance takes precedence. Metadata remains a compatibility
fallback for versioned v1 findings and original in-memory integrations.

Single-event findings use the same first and last time. Aggregate rules retain
their window; for example, `CLD-006` preserves all failed event IDs and the
first-to-last observation range.

Every source CloudTrail finding is accounted for exactly once as an entry or an
omission. The supported omission reasons are `missing-timestamp`,
`invalid-timestamp`, `invalid-time-range`, and `missing-event-id`. Omissions are
visible in both JSON and Markdown so incomplete evidence cannot appear to be
complete coverage.

## Activity Classification

Activity labels describe the observed control-plane action:

| Rule | Activity Type |
| --- | --- |
| `CLD-001`, `CLD-007` | Account access |
| `CLD-002` | Identity protection change |
| `CLD-003` | Network access change |
| `CLD-004` | Data access change |
| `CLD-005` | Authorization change |
| `CLD-006` | Discovery and probing |
| `CLD-008` | Credential persistence |
| `CLD-009` | Trust relationship change |
| `CLD-010` | Monitoring impairment |
| `CLD-011` | Potential destructive impact |

Tests require every built-in CloudTrail rule to have a classification. An
uncataloged custom CloudTrail rule remains compatible, receives
`other-observed-activity`, and uses its v2 finding confidence or
`not-assessed` when confidence is unknown. Migrated v1 built-in findings fall
back to catalog confidence.

These labels are not MITRE ATT&CK tactics or proof that an event was malicious.
For example, repeated access denials can reflect probing, automation errors, or
permission drift.

## Incident Linkage

A timeline entry is linked to an incident only when all three fields agree:

1. Rule ID
2. `resource_type/resource_id`
3. At least one event ID

Time proximity, actor, or source IP alone cannot create a link. This avoids
presenting unrelated activity as one chain, but it can miss relationships that
require session, account, topology, or semantic context.

The report uses linked entries to describe each incident's observed sequence
and add conditional triage context for monitoring impairment, destructive
impact, durable credential or trust changes, and repeated failures. When no
entry can be linked, the report states the evidence gap instead of inventing a
sequence.

## Determinism

Entries are ordered by first time, last time, severity, rule, resource, and
stable entry ID. Event names, event IDs, and incident IDs use sorted unique
lists. A `TLN-` ID is the first 12 uppercase hexadecimal characters of a SHA-256
digest over the rule, resource, normalized time range, and event IDs.

Changing input file order does not change the artifact. Changing the evidence
does change the ID, which prevents an updated observation from silently
retaining the identity of an older one.

## Interpretation Boundary

The timeline establishes observed ordering only. It does not prove:

- Malicious intent or attribution
- That one action caused another
- That all relevant events were collected
- That a correlated incident is a confirmed compromise
- That an activity label represents an attack phase

Analysts should validate change authorization, identity and session context,
surrounding telemetry, collection continuity, and business impact before
reaching an incident conclusion.
