# Remediation Prioritization

The report pipeline converts findings and correlated incidents into a deterministic remediation work queue. The queue is available inside the Markdown report and as a versioned JSON artifact through `--remediation-output`.

The model deliberately uses explainable priority bands instead of a numeric risk score. It does not claim to calculate breach probability, financial impact, or remediation effort.

## Priority Bands

| Priority | Selection Rule | Intended Handling |
| --- | --- | --- |
| `P0` | A critical incident, or a high-severity incident with high correlation confidence | Begin immediate validation, containment, evidence preservation, and control restoration |
| `P1` | Any other incident; a critical finding; or configuration linked to a `P0` incident | Investigate or harden urgently after immediate containment begins |
| `P2` | A high finding, or configuration linked to a non-`P0` incident | Schedule near-term hardening and verification |
| `P3` | A medium, low, or informational finding without incident context | Track as planned security improvement |

Incident response and configuration hardening are separate work types. An incident produces one response item using its recommended actions. Its underlying findings still produce configuration items so that containment does not silently replace permanent remediation.

Within a priority band, incident-response items sort before configuration work. Remaining ties use severity, confidence, module, and a stable action ID. The ordering is deterministic and does not change when input files or findings are supplied in a different order.

## Finding Aggregation

Configuration findings are grouped only when all of these values match:

1. Module.
2. Rule ID.
3. Severity.
4. Finding title.
5. Remediation text.

This combines repeated instances of the same fix while preserving distinct urgency and service-specific remediation. Each action records the number of covered findings and a sorted list of affected resources. Every source finding must belong to exactly one configuration action; the model rejects incomplete accounting.

## Incident Linkage

A finding is linked to an incident only when all conditions match:

1. The finding rule ID appears in the incident.
2. The exact `resource_type/resource_id` value appears in the incident resources.
3. The finding and incident share at least one exact CloudTrail event ID.

This conservative join avoids elevating unrelated findings merely because they share a rule or repeatedly affect the same resource. A finding without event-ID evidence is not automatically linked. A configuration action linked to a `P0` incident becomes `P1`; one linked to another incident becomes at least `P2`.

## Confidence

Incident-response confidence comes from the correlation result. Configuration confidence comes from the built-in rule catalog and describes how directly the evidence supports the rule condition. Custom rules remain compatible but use `not-assessed`; the planner does not invent confidence for external detectors.

Confidence is a tie-breaker and explanatory field. It never overrides the published priority rules or represents certainty that activity is malicious.

## Stable IDs and Contract

Action IDs use `REM-` plus the first 12 uppercase hexadecimal characters of a SHA-256 digest:

- Incident-response IDs are derived from the incident ID.
- Configuration IDs are derived from module, rule, severity, title, and remediation.

The same work definition therefore receives the same ID across repeat runs, while a material change to the work creates a new ID.

The JSON contract is [`remediation-plan-v1.0.schema.json`](../schemas/remediation-plan-v1.0.schema.json). It records source counts, action count, priorities, work types, severity, confidence, rationale, rules, resources, incidents, and required actions.

Generate a standalone plan while creating a report:

```bash
python3 -m cloud_security_lab report \
  --findings reports/generated/iam_findings.json \
  --incidents reports/generated/cloudtrail_incidents.json \
  --remediation-output reports/generated/remediation_plan.json \
  --output reports/generated/cloud_security_report.md
```

## Interpretation Boundary

The plan is an evidence-based triage queue, not an autonomous change plan. It does not know business criticality, data classification, compensating controls outside the supplied evidence, change windows, ownership, dependencies, effort, or whether an action has already been approved. Analysts should add that context before executing remediation.
