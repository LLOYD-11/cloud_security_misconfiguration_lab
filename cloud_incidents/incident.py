"""Shared correlated-incident model and JSON helpers."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from cloud_inputs import JsonBudget, enforce_collection_limit, load_bounded_json

SCHEMA_VERSION = "1.0"
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_CONFIDENCE = frozenset({"low", "medium", "high"})
INCIDENT_ID_PATTERN = re.compile(r"^CTI-[0-9A-F]{12}$")
REQUIRED_TEXT_FIELDS = (
    "incident_id",
    "module",
    "category",
    "title",
    "actor",
    "source_ip",
    "first_seen",
    "last_seen",
    "summary",
)
REQUIRED_LIST_FIELDS = (
    "rule_ids",
    "event_ids",
    "resources",
    "recommended_actions",
    "references",
)


def _parse_utc_timestamp(value: str, field_name: str) -> datetime:
    parse_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(parse_value)
    except ValueError as exc:
        raise ValueError(f"Incident {field_name} must be an ISO 8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"Incident {field_name} must use UTC (Z or +00:00).")
    return parsed


@dataclass(frozen=True)
class Incident:
    incident_id: str
    severity: str
    confidence: str
    module: str
    category: str
    title: str
    actor: str
    source_ip: str
    first_seen: str
    last_seen: str
    event_count: int
    finding_count: int
    rule_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    summary: str = ""
    recommended_actions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.severity, str) or self.severity.lower() not in VALID_SEVERITIES:
            allowed = ", ".join(sorted(VALID_SEVERITIES))
            raise ValueError(f"Incident severity must be one of: {allowed}.")
        object.__setattr__(self, "severity", self.severity.lower())

        if not isinstance(self.confidence, str) or self.confidence.lower() not in VALID_CONFIDENCE:
            allowed = ", ".join(sorted(VALID_CONFIDENCE))
            raise ValueError(f"Incident confidence must be one of: {allowed}.")
        object.__setattr__(self, "confidence", self.confidence.lower())

        for field_name in REQUIRED_TEXT_FIELDS:
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Incident {field_name} must be a non-empty string.")
        if not INCIDENT_ID_PATTERN.fullmatch(self.incident_id):
            raise ValueError("Incident incident_id must use CTI- followed by 12 uppercase hex characters.")

        first_seen = _parse_utc_timestamp(self.first_seen, "first_seen")
        last_seen = _parse_utc_timestamp(self.last_seen, "last_seen")
        if last_seen < first_seen:
            raise ValueError("Incident last_seen must not precede first_seen.")

        for field_name in ("event_count", "finding_count"):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"Incident {field_name} must be a positive integer.")

        for field_name in REQUIRED_LIST_FIELDS:
            value = getattr(self, field_name)
            if not isinstance(value, list) or not value:
                raise ValueError(f"Incident {field_name} must be a non-empty list.")
            if not all(isinstance(item, str) and item.strip() for item in value):
                raise ValueError(f"Incident {field_name} must contain non-empty strings.")
            if len(value) != len(set(value)):
                raise ValueError(f"Incident {field_name} must not contain duplicates.")

        if self.event_count != len(self.event_ids):
            raise ValueError("Incident event_count must equal the number of event_ids.")
        if self.finding_count < len(self.rule_ids):
            raise ValueError("Incident finding_count must not be lower than its distinct rule count.")


def _severity_rank(severity: str) -> int:
    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    return order.get(severity.lower(), 5)


def sort_incidents(incidents: Iterable[Incident]) -> list[Incident]:
    return sorted(
        incidents,
        key=lambda item: (
            _severity_rank(item.severity),
            item.first_seen,
            item.incident_id,
        ),
    )


def incidents_to_dicts(incidents: Iterable[Incident]) -> list[dict[str, Any]]:
    return [asdict(incident) for incident in incidents]


def incident_from_dict(data: dict[str, Any]) -> Incident:
    if not isinstance(data, dict):
        raise ValueError("Each incident must be a JSON object.")

    required_fields = {
        "severity",
        "confidence",
        "event_count",
        "finding_count",
        *REQUIRED_TEXT_FIELDS,
        *REQUIRED_LIST_FIELDS,
    }
    missing_fields = sorted(required_fields.difference(data))
    if missing_fields:
        raise ValueError(f"Incident is missing required fields: {', '.join(missing_fields)}.")
    unexpected_fields = sorted(set(data).difference(required_fields))
    if unexpected_fields:
        raise ValueError(f"Incident contains unsupported fields: {', '.join(unexpected_fields)}.")

    return Incident(
        incident_id=data["incident_id"],
        severity=data["severity"],
        confidence=data["confidence"],
        module=data["module"],
        category=data["category"],
        title=data["title"],
        actor=data["actor"],
        source_ip=data["source_ip"],
        first_seen=data["first_seen"],
        last_seen=data["last_seen"],
        event_count=data["event_count"],
        finding_count=data["finding_count"],
        rule_ids=data["rule_ids"],
        event_ids=data["event_ids"],
        resources=data["resources"],
        summary=data["summary"],
        recommended_actions=data["recommended_actions"],
        references=data["references"],
    )


def write_incidents(path: Path, incidents: Iterable[Incident]) -> None:
    sorted_items = sort_incidents(incidents)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "incident_count": len(sorted_items),
        "incidents": incidents_to_dicts(sorted_items),
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def load_incidents_file(
    path: Path,
    *,
    budget: JsonBudget | None = None,
) -> list[Incident]:
    payload = load_bounded_json(
        path,
        label=f"Incidents file {path}",
        budget=budget,
    )

    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a versioned incidents JSON object.")
    schema_version = payload.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise ValueError(
            f"{path} uses unsupported schema version {schema_version!r}; "
            f"expected {SCHEMA_VERSION!r}."
        )

    incidents = payload.get("incidents")
    if not isinstance(incidents, list):
        raise ValueError(f"{path} must contain an incidents list.")
    enforce_collection_limit(
        len(incidents),
        label=f"Incidents file {path}",
    )
    incident_count = payload.get("incident_count")
    if not isinstance(incident_count, int) or isinstance(incident_count, bool):
        raise ValueError(f"{path} must contain an integer incident_count.")
    if incident_count != len(incidents):
        raise ValueError(
            f"{path} incident_count is {incident_count}, but the file contains "
            f"{len(incidents)} incident(s)."
        )
    return sort_incidents(incident_from_dict(item) for item in incidents)
