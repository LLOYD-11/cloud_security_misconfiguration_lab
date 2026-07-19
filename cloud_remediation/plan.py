"""Build and serialize explainable remediation work queues."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from cloud_findings import (
    Finding,
    evidence_reference_ids,
    severity_rank,
    sort_findings,
)
from cloud_incidents import Incident, sort_incidents
from cloud_rules import get_rule

SCHEMA_VERSION = "1.0"
PRIORITY_ORDER = ("P0", "P1", "P2", "P3")
VALID_PRIORITIES = frozenset(PRIORITY_ORDER)
VALID_WORK_TYPES = frozenset({"incident-response", "configuration"})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_CONFIDENCE = frozenset({"high", "medium", "low", "not-assessed"})
ACTION_ID_PATTERN = re.compile(r"^REM-[0-9A-F]{12}$")
INCIDENT_ID_PATTERN = re.compile(r"^CTI-[0-9A-F]{12}$")


def _require_text(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Remediation {field_name} must be a non-empty string.")


def _validate_unique_strings(
    value: Any,
    field_name: str,
    *,
    allow_empty: bool = False,
    require_sorted: bool = False,
) -> None:
    if not isinstance(value, list) or (not value and not allow_empty):
        qualifier = "a list" if allow_empty else "a non-empty list"
        raise ValueError(f"Remediation {field_name} must be {qualifier}.")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(
            f"Remediation {field_name} must contain non-empty strings."
        )
    if len(value) != len(set(value)):
        raise ValueError(f"Remediation {field_name} must not contain duplicates.")
    if require_sorted and value != sorted(value):
        raise ValueError(
            f"Remediation {field_name} must use deterministic sorted order."
        )


@dataclass(frozen=True)
class RemediationAction:
    """One prioritized response or configuration work item."""

    action_id: str
    priority: str
    work_type: str
    severity: str
    confidence: str
    module: str
    title: str
    rationale: str
    finding_count: int
    rule_ids: list[str]
    resources: list[str]
    incident_ids: list[str]
    actions: list[str]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.action_id, str)
            or ACTION_ID_PATTERN.fullmatch(self.action_id) is None
        ):
            raise ValueError(
                "Remediation action_id must use REM- followed by 12 uppercase "
                "hexadecimal characters."
            )
        if self.priority not in VALID_PRIORITIES:
            raise ValueError(
                "Remediation priority must be one of: "
                + ", ".join(PRIORITY_ORDER)
                + "."
            )
        if self.work_type not in VALID_WORK_TYPES:
            raise ValueError(
                "Remediation work_type must be configuration or incident-response."
            )
        if self.severity not in VALID_SEVERITIES:
            raise ValueError("Remediation severity is invalid.")
        if self.confidence not in VALID_CONFIDENCE:
            raise ValueError("Remediation confidence is invalid.")
        for field_name in ("module", "title", "rationale"):
            _require_text(getattr(self, field_name), field_name)
        if (
            not isinstance(self.finding_count, int)
            or isinstance(self.finding_count, bool)
            or self.finding_count <= 0
        ):
            raise ValueError(
                "Remediation finding_count must be a positive integer."
            )
        _validate_unique_strings(
            self.rule_ids,
            "rule_ids",
            require_sorted=True,
        )
        _validate_unique_strings(
            self.resources,
            "resources",
            require_sorted=True,
        )
        _validate_unique_strings(
            self.incident_ids,
            "incident_ids",
            allow_empty=True,
            require_sorted=True,
        )
        _validate_unique_strings(self.actions, "actions")
        if not all(
            INCIDENT_ID_PATTERN.fullmatch(incident_id)
            for incident_id in self.incident_ids
        ):
            raise ValueError("Remediation incident_ids contain an invalid ID.")
        if self.work_type == "incident-response" and len(self.incident_ids) != 1:
            raise ValueError(
                "Incident-response remediation must reference exactly one incident."
            )


@dataclass(frozen=True)
class RemediationPlan:
    """Versioned remediation actions derived from one report input set."""

    schema_version: str
    source_finding_count: int
    source_incident_count: int
    actions: tuple[RemediationAction, ...]

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported remediation plan schema version "
                f"{self.schema_version!r}; expected {SCHEMA_VERSION!r}."
            )
        for field_name in ("source_finding_count", "source_incident_count"):
            value = getattr(self, field_name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(
                    f"Remediation plan {field_name} must be a non-negative integer."
                )
        if not isinstance(self.actions, tuple):
            raise ValueError("Remediation plan actions must be a tuple.")
        if list(self.actions) != sort_remediation_actions(self.actions):
            raise ValueError(
                "Remediation plan actions must use deterministic priority order."
            )
        action_ids = [action.action_id for action in self.actions]
        if len(action_ids) != len(set(action_ids)):
            raise ValueError("Remediation plan action IDs must be unique.")
        configuration_finding_count = sum(
            action.finding_count
            for action in self.actions
            if action.work_type == "configuration"
        )
        if configuration_finding_count != self.source_finding_count:
            raise ValueError(
                "Remediation configuration actions must account for every source "
                "finding exactly once."
            )
        response_actions = [
            action
            for action in self.actions
            if action.work_type == "incident-response"
        ]
        if len(response_actions) != self.source_incident_count:
            raise ValueError(
                "Remediation incident-response actions must account for every "
                "source incident exactly once."
            )
        response_incident_ids = [
            action.incident_ids[0] for action in response_actions
        ]
        if len(response_incident_ids) != len(set(response_incident_ids)):
            raise ValueError(
                "Remediation incident-response actions must reference unique incidents."
            )


def _confidence_rank(confidence: str) -> int:
    order = {"high": 0, "medium": 1, "low": 2, "not-assessed": 3}
    return order[confidence]


def sort_remediation_actions(
    actions: Iterable[RemediationAction],
) -> list[RemediationAction]:
    """Sort actions by declared priority and deterministic evidence tie-breakers."""

    return sorted(
        actions,
        key=lambda item: (
            PRIORITY_ORDER.index(item.priority),
            0 if item.work_type == "incident-response" else 1,
            severity_rank(item.severity),
            _confidence_rank(item.confidence),
            item.module,
            item.action_id,
        ),
    )


def _action_id(*parts: str) -> str:
    canonical = json.dumps(parts, ensure_ascii=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12].upper()
    return f"REM-{digest}"


def _incident_priority(incident: Incident) -> str:
    if incident.severity == "critical" or (
        incident.severity == "high" and incident.confidence == "high"
    ):
        return "P0"
    return "P1"


def _finding_incident_ids(
    finding: Finding,
    incidents: Iterable[Incident],
) -> list[str]:
    resource = f"{finding.resource_type}/{finding.resource_id}"
    event_ids = set(evidence_reference_ids(finding, "cloudtrail-event"))
    if not event_ids:
        event_ids_raw = finding.metadata.get("event_ids") or finding.metadata.get(
            "event_id"
        )
        if not event_ids_raw:
            return []
        event_ids = {
            event_id.strip()
            for event_id in event_ids_raw.split(",")
            if event_id.strip()
        }
    if not event_ids:
        return []
    return sorted(
        incident.incident_id
        for incident in incidents
        if finding.rule_id in incident.rule_ids
        and resource in incident.resources
        and event_ids.intersection(incident.event_ids)
    )


def _configuration_priority(
    severity: str,
    incident_ids: Iterable[str],
    p0_incident_ids: set[str],
) -> str:
    linked_incidents = set(incident_ids)
    if severity == "critical" or linked_incidents.intersection(p0_incident_ids):
        return "P1"
    if severity == "high" or linked_incidents:
        return "P2"
    return "P3"


def _incident_action(incident: Incident) -> RemediationAction:
    priority = _incident_priority(incident)
    rule_count = len(incident.rule_ids)
    event_label = "event" if incident.event_count == 1 else "events"
    rule_label = "rule" if rule_count == 1 else "rules"
    rationale = (
        f"{incident.severity.capitalize()}-severity correlated incident "
        f"{incident.incident_id} has {incident.confidence} confidence across "
        f"{rule_count} {rule_label} and {incident.event_count} {event_label}."
    )
    return RemediationAction(
        action_id=_action_id("incident-response", incident.incident_id),
        priority=priority,
        work_type="incident-response",
        severity=incident.severity,
        confidence=incident.confidence,
        module=incident.module,
        title=f"Respond: {incident.title}",
        rationale=rationale,
        finding_count=incident.finding_count,
        rule_ids=sorted(incident.rule_ids),
        resources=sorted(incident.resources),
        incident_ids=[incident.incident_id],
        actions=list(incident.recommended_actions),
    )


def _configuration_actions(
    findings: Iterable[Finding],
    incidents: list[Incident],
) -> list[RemediationAction]:
    groups: dict[
        tuple[str, str, str, str, str],
        list[tuple[Finding, list[str]]],
    ] = defaultdict(list)
    for finding in sort_findings(findings):
        incident_ids = _finding_incident_ids(finding, incidents)
        key = (
            finding.module,
            finding.rule_id,
            finding.severity,
            finding.title,
            finding.remediation,
        )
        groups[key].append((finding, incident_ids))

    p0_incident_ids = {
        incident.incident_id
        for incident in incidents
        if _incident_priority(incident) == "P0"
    }
    actions: list[RemediationAction] = []
    for (
        module,
        rule_id,
        severity,
        title,
        remediation,
    ), group in sorted(groups.items()):
        resources = sorted(
            {
                f"{finding.resource_type}/{finding.resource_id}"
                for finding, _ in group
            }
        )
        incident_ids = sorted(
            {
                incident_id
                for _, related_ids in group
                for incident_id in related_ids
            }
        )
        priority = _configuration_priority(
            severity,
            incident_ids,
            p0_incident_ids,
        )
        rule = get_rule(rule_id)
        finding_confidences = {
            finding.confidence
            for finding, _ in group
            if finding.confidence != "unknown"
        }
        confidence = (
            next(iter(finding_confidences))
            if len(finding_confidences) == 1
            else rule.confidence
            if rule is not None
            else "not-assessed"
        )
        finding_label = "finding" if len(group) == 1 else "findings"
        resource_label = "resource" if len(resources) == 1 else "resources"
        affect_verb = "affects" if len(group) == 1 else "affect"
        rationale = (
            f"{len(group)} {severity} {finding_label} for {rule_id} {affect_verb} "
            f"{len(resources)} {resource_label}."
        )
        if incident_ids:
            rationale += (
                " Related incident context: "
                + ", ".join(incident_ids)
                + "."
            )
        actions.append(
            RemediationAction(
                action_id=_action_id(
                    "configuration",
                    module,
                    rule_id,
                    severity,
                    title,
                    remediation,
                ),
                priority=priority,
                work_type="configuration",
                severity=severity,
                confidence=confidence,
                module=module,
                title=f"Remediate: {title}",
                rationale=rationale,
                finding_count=len(group),
                rule_ids=[rule_id],
                resources=resources,
                incident_ids=incident_ids,
                actions=[remediation],
            )
        )
    return actions


def build_remediation_plan(
    findings: Iterable[Finding],
    incidents: Iterable[Incident],
) -> RemediationPlan:
    """Build a complete deterministic response and hardening work queue."""

    sorted_findings = sort_findings(findings)
    sorted_incidents = sort_incidents(incidents)
    actions = [
        *(_incident_action(incident) for incident in sorted_incidents),
        *_configuration_actions(sorted_findings, sorted_incidents),
    ]
    return RemediationPlan(
        schema_version=SCHEMA_VERSION,
        source_finding_count=len(sorted_findings),
        source_incident_count=len(sorted_incidents),
        actions=tuple(sort_remediation_actions(actions)),
    )


def remediation_plan_to_dict(plan: RemediationPlan) -> dict[str, Any]:
    """Convert a plan to its versioned JSON representation."""

    return {
        "schema_version": plan.schema_version,
        "source_finding_count": plan.source_finding_count,
        "source_incident_count": plan.source_incident_count,
        "action_count": len(plan.actions),
        "actions": [asdict(action) for action in plan.actions],
    }


def _remediation_action_from_dict(data: Any) -> RemediationAction:
    fields = {
        "action_id",
        "priority",
        "work_type",
        "severity",
        "confidence",
        "module",
        "title",
        "rationale",
        "finding_count",
        "rule_ids",
        "resources",
        "incident_ids",
        "actions",
    }
    if not isinstance(data, dict):
        raise ValueError("Each remediation action must be a JSON object.")
    missing = sorted(fields.difference(data))
    unexpected = sorted(set(data).difference(fields))
    if missing:
        raise ValueError(
            "Remediation action is missing fields: " + ", ".join(missing) + "."
        )
    if unexpected:
        raise ValueError(
            "Remediation action contains unsupported fields: "
            + ", ".join(unexpected)
            + "."
        )
    return RemediationAction(**data)


def remediation_plan_from_dict(data: Any) -> RemediationPlan:
    """Strictly deserialize a versioned remediation plan."""

    fields = {
        "schema_version",
        "source_finding_count",
        "source_incident_count",
        "action_count",
        "actions",
    }
    if not isinstance(data, dict):
        raise ValueError("Remediation plan must be a versioned JSON object.")
    missing = sorted(fields.difference(data))
    unexpected = sorted(set(data).difference(fields))
    if missing:
        raise ValueError(
            "Remediation plan is missing fields: " + ", ".join(missing) + "."
        )
    if unexpected:
        raise ValueError(
            "Remediation plan contains unsupported fields: "
            + ", ".join(unexpected)
            + "."
        )
    raw_actions = data["actions"]
    if not isinstance(raw_actions, list):
        raise ValueError("Remediation plan actions must be a JSON list.")
    action_count = data["action_count"]
    if not isinstance(action_count, int) or isinstance(action_count, bool):
        raise ValueError("Remediation plan action_count must be an integer.")
    if action_count != len(raw_actions):
        raise ValueError(
            f"Remediation plan action_count is {action_count}, but it contains "
            f"{len(raw_actions)} action(s)."
        )
    return RemediationPlan(
        schema_version=data["schema_version"],
        source_finding_count=data["source_finding_count"],
        source_incident_count=data["source_incident_count"],
        actions=tuple(
            _remediation_action_from_dict(action) for action in raw_actions
        ),
    )


def write_remediation_plan(path: Path, plan: RemediationPlan) -> None:
    """Write one deterministic remediation plan."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(remediation_plan_to_dict(plan), handle, indent=2)
        handle.write("\n")


def load_remediation_plan_file(path: Path) -> RemediationPlan:
    """Load and validate one remediation plan file."""

    with path.open("r", encoding="utf-8") as handle:
        return remediation_plan_from_dict(json.load(handle))
