# CloudTrail Incident Correlation

The CloudTrail detector produces two related but distinct artifacts:

- Findings describe one rule match or one bounded aggregate such as an API failure spike.
- Incidents group related findings into a triage unit without discarding the underlying evidence.

Incident output uses
[`incidents-v1.0.schema.json`](../schemas/incidents-v1.0.schema.json).
Correlation consumes findings v2 provenance while retaining versioned v1
compatibility.

## Correlation Keys and Window

The default correlation window is 30 minutes and can be changed with `--correlation-window-minutes`.

Signals are eligible for the same incident only when they have:

1. The same finding account, including `unknown` when unavailable.
2. The same normalized actor.
3. The same source IP or source name.
4. Start times within one bounded window anchored at the first signal.

Signals are assigned to deterministic, non-overlapping clusters. When the next signal falls outside the anchor window, it starts a new cluster instead of being reused in two incidents.

Signal time and event identity come first from v2 `observed_at` and
`cloudtrail-event` evidence references. Legacy `event_time`, `first_seen`,
`last_seen`, `event_id`, and `event_ids` metadata remain a fallback for
versioned v1 findings.

The actor is derived from `userIdentity.userName`, then the assumed-role session issuer, ARN, principal ID, or identity type. Source values come directly from CloudTrail `sourceIPAddress`; AWS service names are therefore possible as well as IP addresses.

The grouping intentionally does not correlate on actor alone. A principal used
from two accounts or two sources can represent different sessions, automation,
or concurrent activity and remains separate.

## Qualification

A cluster becomes an incident when it contains:

- At least two distinct rule IDs across at least two distinct event IDs; or
- One `CLD-006` failure-spike finding that already aggregates multiple event IDs.

Repeated findings for the same rule do not create a multi-signal incident by themselves. This prevents ordinary repeated administration, such as two bucket-policy updates, from being presented as a richer attack chain without another signal.

Event IDs are de-duplicated before counting. Native CloudTrail GUIDs are used when available; simplified events without IDs receive deterministic input-order fallback identifiers.

## Severity, Confidence, and Identity

Incident severity equals the highest severity among its constituent findings. Correlation never raises severity simply because more events were observed.

Confidence is:

- `high` for three or more distinct rules;
- `medium` for two distinct rules or an independently aggregated API-failure incident.

This confidence describes the strength of the correlation, not certainty that the activity is malicious.

Each incident ID uses the prefix `CTI-` followed by the first 12 hexadecimal characters of a SHA-256 digest over the actor, source, time range, sorted rule IDs, and sorted event IDs. Re-running the same evidence therefore produces the same ID.

## Evidence Boundary

Correlation is deterministic and explainable, but deliberately conservative:

- It does not baseline normal working hours, approved source ranges, user agents, or resource criticality.
- It does not join events across accounts or sources.
- Shared credentials, NAT, proxies, and AWS service-originated calls can blur actor or source identity.
- Missing CloudTrail fields and log-delivery gaps can break a sequence.
- An incident is a triage lead, not proof of compromise.

CloudTrail documents `eventID` as the unique event identifier and `sourceIPAddress` as the request source. Its `additionalEventData` can contain `MFAUsed` for console sign-ins. See [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) and [CloudTrail user identity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html).

## Run

```bash
python3 -m cloud_security_lab analyze cloudtrail \
  sample_data/cloudtrail/sample_cloudtrail_events.json \
  --output reports/generated/cloudtrail_findings.json \
  --incidents-output reports/generated/cloudtrail_incidents.json \
  --correlation-window-minutes 30
```

Include incidents in a report:

```bash
python3 -m cloud_security_lab report \
  --findings reports/generated/cloudtrail_findings.json \
  --incidents reports/generated/cloudtrail_incidents.json \
  --output reports/generated/cloud_security_report.md
```
