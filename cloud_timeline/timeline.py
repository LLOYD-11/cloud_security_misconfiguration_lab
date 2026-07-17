"""Build and serialize chronological CloudTrail finding narratives."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from cloud_findings import Finding, severity_rank, sort_findings
from cloud_incidents import Incident, sort_incidents
from cloud_rules import get_rule

SCHEMA_VERSION = "1.0"
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_CONFIDENCE = frozenset({"high", "medium", "low", "not-assessed"})
VALID_OMISSION_REASONS = frozenset(
    {
        "missing-timestamp",
        "invalid-timestamp",
        "invalid-time-range",
        "missing-event-id",
    }
)
ENTRY_ID_PATTERN = re.compile(r"^TLN-[0-9A-F]{12}$")
INCIDENT_ID_PATTERN = re.compile(r"^CTI-[0-9A-F]{12}$")

ACTIVITY_LABELS = {
    "account-access": "Account access",
    "identity-protection-change": "Identity protection change",
    "network-access-change": "Network access change",
    "data-access-change": "Data access change",
    "authorization-change": "Authorization change",
    "discovery-and-probing": "Discovery and probing",
    "credential-persistence": "Credential persistence",
    "trust-relationship-change": "Trust relationship change",
    "monitoring-impairment": "Monitoring impairment",
    "destructive-impact": "Potential destructive impact",
    "other-observed-activity": "Other observed activity",
}
VALID_ACTIVITY_TYPES = frozenset(ACTIVITY_LABELS)
RULE_ACTIVITY_TYPES = {
    "CLD-001": "account-access",
    "CLD-002": "identity-protection-change",
    "CLD-003": "network-access-change",
    "CLD-004": "data-access-change",
    "CLD-005": "authorization-change",
    "CLD-006": "discovery-and-probing",
    "CLD-007": "account-access",
    "CLD-008": "credential-persistence",
    "CLD-009": "trust-relationship-change",
    "CLD-010": "monitoring-impairment",
    "CLD-011": "destructive-impact",
}


def _require_text(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Timeline {field_name} must be a non-empty string.")


def _validate_unique_strings(
    value: Any,
    field_name: str,
    *,
    allow_empty: bool = False,
    require_sorted: bool = False,
) -> None:
    if not isinstance(value, list) or (not value and not allow_empty):
        qualifier = "a list" if allow_empty else "a non-empty list"
        raise ValueError(f"Timeline {field_name} must be {qualifier}.")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"Timeline {field_name} must contain non-empty strings.")
    if len(value) != len(set(value)):
        raise ValueError(f"Timeline {field_name} must not contain duplicates.")
    if require_sorted and value != sorted(value):
        raise ValueError(
            f"Timeline {field_name} must use deterministic sorted order."
        )


def _parse_utc_timestamp(value: str, field_name: str) -> datetime:
    parse_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(parse_value)
    except ValueError as exc:
        raise ValueError(
            f"Timeline {field_name} must be an ISO 8601 timestamp."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"Timeline {field_name} must use UTC (Z or +00:00).")
    return parsed


def _isoformat_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class TimelineEntry:
    """One timestamped finding signal with optional incident context."""

    entry_id: str
    first_seen: str
    last_seen: str
    severity: str
    confidence: str
    activity_type: str
    rule_id: str
    title: str
    actor: str
    source_ip: str
    event_names: list[str]
    event_ids: list[str]
    resource: str
    incident_ids: list[str]
    observation: str
    significance: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.entry_id, str)
            or ENTRY_ID_PATTERN.fullmatch(self.entry_id) is None
        ):
            raise ValueError(
                "Timeline entry_id must use TLN- followed by 12 uppercase "
                "hexadecimal characters."
            )
        first_seen = _parse_utc_timestamp(self.first_seen, "first_seen")
        last_seen = _parse_utc_timestamp(self.last_seen, "last_seen")
        if last_seen < first_seen:
            raise ValueError("Timeline last_seen must not precede first_seen.")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError("Timeline severity is invalid.")
        if self.confidence not in VALID_CONFIDENCE:
            raise ValueError("Timeline confidence is invalid.")
        if self.activity_type not in VALID_ACTIVITY_TYPES:
            raise ValueError("Timeline activity_type is invalid.")
        for field_name in (
            "rule_id",
            "title",
            "actor",
            "source_ip",
            "resource",
            "observation",
            "significance",
        ):
            _require_text(getattr(self, field_name), field_name)
        _validate_unique_strings(
            self.event_names,
            "event_names",
            allow_empty=True,
            require_sorted=True,
        )
        _validate_unique_strings(
            self.event_ids,
            "event_ids",
            require_sorted=True,
        )
        _validate_unique_strings(
            self.incident_ids,
            "incident_ids",
            allow_empty=True,
            require_sorted=True,
        )
        if not all(
            INCIDENT_ID_PATTERN.fullmatch(incident_id)
            for incident_id in self.incident_ids
        ):
            raise ValueError("Timeline incident_ids contain an invalid ID.")


@dataclass(frozen=True)
class TimelineOmission:
    """One CloudTrail finding that lacked usable chronological evidence."""

    rule_id: str
    resource: str
    reason: str

    def __post_init__(self) -> None:
        _require_text(self.rule_id, "omission rule_id")
        _require_text(self.resource, "omission resource")
        if self.reason not in VALID_OMISSION_REASONS:
            raise ValueError("Timeline omission reason is invalid.")


@dataclass(frozen=True)
class AttackTimeline:
    """Versioned chronological view of CloudTrail finding signals."""

    schema_version: str
    source_cloudtrail_finding_count: int
    source_incident_count: int
    entries: tuple[TimelineEntry, ...]
    omissions: tuple[TimelineOmission, ...]

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported attack timeline schema version "
                f"{self.schema_version!r}; expected {SCHEMA_VERSION!r}."
            )
        for field_name in (
            "source_cloudtrail_finding_count",
            "source_incident_count",
        ):
            value = getattr(self, field_name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(
                    f"Attack timeline {field_name} must be a non-negative integer."
                )
        if not isinstance(self.entries, tuple):
            raise ValueError("Attack timeline entries must be a tuple.")
        if not isinstance(self.omissions, tuple):
            raise ValueError("Attack timeline omissions must be a tuple.")
        if list(self.entries) != sort_timeline_entries(self.entries):
            raise ValueError(
                "Attack timeline entries must use deterministic chronological order."
            )
        if list(self.omissions) != sorted(
            self.omissions,
            key=lambda item: (item.rule_id, item.resource, item.reason),
        ):
            raise ValueError(
                "Attack timeline omissions must use deterministic sorted order."
            )
        entry_ids = [entry.entry_id for entry in self.entries]
        if len(entry_ids) != len(set(entry_ids)):
            raise ValueError("Attack timeline entry IDs must be unique.")
        omission_keys = [
            (item.rule_id, item.resource, item.reason) for item in self.omissions
        ]
        if len(omission_keys) != len(set(omission_keys)):
            raise ValueError("Attack timeline omissions must be unique.")
        if len(self.entries) + len(self.omissions) != (
            self.source_cloudtrail_finding_count
        ):
            raise ValueError(
                "Attack timeline entries and omissions must account for every "
                "source CloudTrail finding exactly once."
            )


@dataclass(frozen=True)
class IncidentNarrative:
    """Reviewer-facing context derived from one incident and its timeline entries."""

    incident_id: str
    observed_sequence: str
    analyst_context: str


def activity_label(activity_type: str) -> str:
    """Return the reviewer-facing label for one activity classification."""

    try:
        return ACTIVITY_LABELS[activity_type]
    except KeyError as exc:
        raise ValueError(f"Unknown timeline activity type {activity_type!r}.") from exc


def sort_timeline_entries(
    entries: Iterable[TimelineEntry],
) -> list[TimelineEntry]:
    """Sort timeline entries chronologically with deterministic tie-breakers."""

    return sorted(
        entries,
        key=lambda item: (
            _parse_utc_timestamp(item.first_seen, "first_seen"),
            _parse_utc_timestamp(item.last_seen, "last_seen"),
            severity_rank(item.severity),
            item.rule_id,
            item.resource,
            item.entry_id,
        ),
    )


def _entry_id(
    *,
    rule_id: str,
    resource: str,
    first_seen: str,
    last_seen: str,
    event_ids: list[str],
) -> str:
    canonical = json.dumps(
        {
            "rule_id": rule_id,
            "resource": resource,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "event_ids": event_ids,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12].upper()
    return f"TLN-{digest}"


def _split_metadata_values(value: str | None) -> list[str]:
    if not value:
        return []
    return sorted(
        {
            item.strip()
            for item in value.split(",")
            if item.strip()
        }
    )


def _linked_incident_ids(
    finding: Finding,
    event_ids: set[str],
    incidents: Iterable[Incident],
) -> list[str]:
    resource = f"{finding.resource_type}/{finding.resource_id}"
    return sorted(
        incident.incident_id
        for incident in incidents
        if finding.rule_id in incident.rule_ids
        and resource in incident.resources
        and event_ids.intersection(incident.event_ids)
    )


def _timeline_item(
    finding: Finding,
    incidents: list[Incident],
) -> TimelineEntry | TimelineOmission:
    resource = f"{finding.resource_type}/{finding.resource_id}"
    first_seen_raw = finding.metadata.get("first_seen") or finding.metadata.get(
        "event_time"
    )
    last_seen_raw = finding.metadata.get("last_seen") or first_seen_raw
    if not first_seen_raw or not last_seen_raw:
        return TimelineOmission(
            rule_id=finding.rule_id,
            resource=resource,
            reason="missing-timestamp",
        )
    try:
        first_seen_value = _parse_utc_timestamp(first_seen_raw, "first_seen")
        last_seen_value = _parse_utc_timestamp(last_seen_raw, "last_seen")
    except ValueError:
        return TimelineOmission(
            rule_id=finding.rule_id,
            resource=resource,
            reason="invalid-timestamp",
        )
    if last_seen_value < first_seen_value:
        return TimelineOmission(
            rule_id=finding.rule_id,
            resource=resource,
            reason="invalid-time-range",
        )
    first_seen = _isoformat_utc(first_seen_value)
    last_seen = _isoformat_utc(last_seen_value)
    event_ids = _split_metadata_values(
        finding.metadata.get("event_ids") or finding.metadata.get("event_id")
    )
    if not event_ids:
        return TimelineOmission(
            rule_id=finding.rule_id,
            resource=resource,
            reason="missing-event-id",
        )
    event_names = _split_metadata_values(
        finding.metadata.get("event_names") or finding.metadata.get("event_name")
    )
    rule = get_rule(finding.rule_id)
    confidence = rule.confidence if rule is not None else "not-assessed"
    activity_type = RULE_ACTIVITY_TYPES.get(
        finding.rule_id,
        "other-observed-activity",
    )
    incident_ids = _linked_incident_ids(
        finding,
        set(event_ids),
        incidents,
    )
    return TimelineEntry(
        entry_id=_entry_id(
            rule_id=finding.rule_id,
            resource=resource,
            first_seen=first_seen,
            last_seen=last_seen,
            event_ids=event_ids,
        ),
        first_seen=first_seen,
        last_seen=last_seen,
        severity=finding.severity,
        confidence=confidence,
        activity_type=activity_type,
        rule_id=finding.rule_id,
        title=finding.title,
        actor=finding.metadata.get("actor") or "unknown-actor",
        source_ip=finding.metadata.get("source_ip") or "unknown-source",
        event_names=event_names,
        event_ids=event_ids,
        resource=resource,
        incident_ids=incident_ids,
        observation=finding.evidence,
        significance=finding.impact,
    )


def build_attack_timeline(
    findings: Iterable[Finding],
    incidents: Iterable[Incident],
) -> AttackTimeline:
    """Build a deterministic timeline from CloudTrail finding metadata."""

    cloudtrail_findings = [
        finding
        for finding in sort_findings(findings)
        if finding.module == "cloudtrail"
    ]
    sorted_incidents = [
        incident
        for incident in sort_incidents(incidents)
        if incident.module == "cloudtrail"
    ]
    items = [
        _timeline_item(finding, sorted_incidents)
        for finding in cloudtrail_findings
    ]
    entries = [
        item for item in items if isinstance(item, TimelineEntry)
    ]
    omissions = [
        item for item in items if isinstance(item, TimelineOmission)
    ]
    return AttackTimeline(
        schema_version=SCHEMA_VERSION,
        source_cloudtrail_finding_count=len(cloudtrail_findings),
        source_incident_count=len(sorted_incidents),
        entries=tuple(sort_timeline_entries(entries)),
        omissions=tuple(
            sorted(
                omissions,
                key=lambda item: (item.rule_id, item.resource, item.reason),
            )
        ),
    )


def _duration_label(first_seen: str, last_seen: str) -> str:
    duration = int(
        (
            _parse_utc_timestamp(last_seen, "last_seen")
            - _parse_utc_timestamp(first_seen, "first_seen")
        ).total_seconds()
    )
    if duration % 60 == 0:
        minutes = duration // 60
        unit = "minute" if minutes == 1 else "minutes"
        return f"{minutes} {unit}"
    unit = "second" if duration == 1 else "seconds"
    return f"{duration} {unit}"


def build_incident_narrative(
    incident: Incident,
    timeline: AttackTimeline,
) -> IncidentNarrative:
    """Explain one incident without turning chronology into asserted causation."""

    entries = [
        entry
        for entry in timeline.entries
        if incident.incident_id in entry.incident_ids
    ]
    if not entries:
        return IncidentNarrative(
            incident_id=incident.incident_id,
            observed_sequence=(
                "No timeline entry could be linked from the supplied finding "
                "evidence; review event IDs and report inputs."
            ),
            analyst_context=(
                f"The incident remains {incident.severity} severity with "
                f"{incident.confidence} correlation confidence. Its time range "
                "comes from the incident artifact, but this report cannot add "
                "finding-level chronology."
            ),
        )

    ordered_activity_types = list(
        dict.fromkeys(entry.activity_type for entry in entries)
    )
    activity_sequence = " -> ".join(
        activity_label(activity_type)
        for activity_type in ordered_activity_types
    )
    entry_label = "entry" if len(entries) == 1 else "entries"
    entry_verb = "represents" if len(entries) == 1 else "represent"
    observed_sequence = (
        f"{len(entries)} linked timeline {entry_label} {entry_verb} "
        f"{incident.event_count} event"
        f"{'' if incident.event_count == 1 else 's'} across "
        f"{len(incident.resources)} resource"
        f"{'' if len(incident.resources) == 1 else 's'} over "
        f"{_duration_label(incident.first_seen, incident.last_seen)}. "
        f"Chronological activity types: {activity_sequence}."
    )

    context = [
        (
            f"This is a {incident.severity}-severity, "
            f"{incident.confidence}-confidence correlation and should be "
            "validated against change authorization and surrounding telemetry."
        )
    ]
    activity_type_set = set(ordered_activity_types)
    if "monitoring-impairment" in activity_type_set:
        context.append(
            "Monitoring impairment increases the urgency of checking telemetry "
            "continuity and alternate evidence sources."
        )
    if "destructive-impact" in activity_type_set:
        context.append(
            "A potential destructive-impact action makes recovery dependencies "
            "and rollback options part of immediate triage."
        )
    if activity_type_set.intersection(
        {"credential-persistence", "trust-relationship-change"}
    ):
        context.append(
            "Credential or trust changes mean containment should include durable "
            "access paths, not only the initiating session."
        )
    if "discovery-and-probing" in activity_type_set:
        context.append(
            "Repeated denials can indicate probing, but automation errors and "
            "permission drift remain plausible alternatives."
        )
    context.append(
        "The timeline establishes observed ordering, not malicious intent or "
        "proof that one action caused the next."
    )
    return IncidentNarrative(
        incident_id=incident.incident_id,
        observed_sequence=observed_sequence,
        analyst_context=" ".join(context),
    )


def attack_timeline_to_dict(timeline: AttackTimeline) -> dict[str, Any]:
    """Convert a timeline to its versioned JSON representation."""

    return {
        "schema_version": timeline.schema_version,
        "source_cloudtrail_finding_count": (
            timeline.source_cloudtrail_finding_count
        ),
        "source_incident_count": timeline.source_incident_count,
        "entry_count": len(timeline.entries),
        "omission_count": len(timeline.omissions),
        "entries": [asdict(entry) for entry in timeline.entries],
        "omissions": [asdict(omission) for omission in timeline.omissions],
    }


def _timeline_entry_from_dict(data: Any) -> TimelineEntry:
    fields = {
        "entry_id",
        "first_seen",
        "last_seen",
        "severity",
        "confidence",
        "activity_type",
        "rule_id",
        "title",
        "actor",
        "source_ip",
        "event_names",
        "event_ids",
        "resource",
        "incident_ids",
        "observation",
        "significance",
    }
    if not isinstance(data, dict):
        raise ValueError("Each timeline entry must be a JSON object.")
    missing = sorted(fields.difference(data))
    unexpected = sorted(set(data).difference(fields))
    if missing:
        raise ValueError(
            "Timeline entry is missing fields: " + ", ".join(missing) + "."
        )
    if unexpected:
        raise ValueError(
            "Timeline entry contains unsupported fields: "
            + ", ".join(unexpected)
            + "."
        )
    return TimelineEntry(**data)


def _timeline_omission_from_dict(data: Any) -> TimelineOmission:
    fields = {"rule_id", "resource", "reason"}
    if not isinstance(data, dict):
        raise ValueError("Each timeline omission must be a JSON object.")
    missing = sorted(fields.difference(data))
    unexpected = sorted(set(data).difference(fields))
    if missing:
        raise ValueError(
            "Timeline omission is missing fields: " + ", ".join(missing) + "."
        )
    if unexpected:
        raise ValueError(
            "Timeline omission contains unsupported fields: "
            + ", ".join(unexpected)
            + "."
        )
    return TimelineOmission(**data)


def attack_timeline_from_dict(data: Any) -> AttackTimeline:
    """Strictly deserialize one versioned attack timeline."""

    fields = {
        "schema_version",
        "source_cloudtrail_finding_count",
        "source_incident_count",
        "entry_count",
        "omission_count",
        "entries",
        "omissions",
    }
    if not isinstance(data, dict):
        raise ValueError("Attack timeline must be a versioned JSON object.")
    missing = sorted(fields.difference(data))
    unexpected = sorted(set(data).difference(fields))
    if missing:
        raise ValueError(
            "Attack timeline is missing fields: " + ", ".join(missing) + "."
        )
    if unexpected:
        raise ValueError(
            "Attack timeline contains unsupported fields: "
            + ", ".join(unexpected)
            + "."
        )
    entries = data["entries"]
    omissions = data["omissions"]
    if not isinstance(entries, list):
        raise ValueError("Attack timeline entries must be a JSON list.")
    if not isinstance(omissions, list):
        raise ValueError("Attack timeline omissions must be a JSON list.")
    for count_field, values in (
        ("entry_count", entries),
        ("omission_count", omissions),
    ):
        declared_count = data[count_field]
        if not isinstance(declared_count, int) or isinstance(
            declared_count, bool
        ):
            raise ValueError(f"Attack timeline {count_field} must be an integer.")
        if declared_count != len(values):
            raise ValueError(
                f"Attack timeline {count_field} is {declared_count}, but the file "
                f"contains {len(values)} item(s)."
            )
    return AttackTimeline(
        schema_version=data["schema_version"],
        source_cloudtrail_finding_count=data[
            "source_cloudtrail_finding_count"
        ],
        source_incident_count=data["source_incident_count"],
        entries=tuple(_timeline_entry_from_dict(entry) for entry in entries),
        omissions=tuple(
            _timeline_omission_from_dict(omission) for omission in omissions
        ),
    )


def write_attack_timeline(path: Path, timeline: AttackTimeline) -> None:
    """Write one deterministic attack timeline."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(attack_timeline_to_dict(timeline), handle, indent=2)
        handle.write("\n")


def load_attack_timeline_file(path: Path) -> AttackTimeline:
    """Load and validate one attack timeline file."""

    with path.open("r", encoding="utf-8") as handle:
        return attack_timeline_from_dict(json.load(handle))
