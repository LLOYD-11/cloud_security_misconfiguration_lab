"""Correlate CloudTrail findings into deterministic triage incidents."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cloud_findings import Finding, severity_rank
from cloud_incidents import Incident, sort_incidents

DEFAULT_CORRELATION_WINDOW_MINUTES = 30


@dataclass(frozen=True)
class _CorrelationSignal:
    finding: Finding
    first_seen: datetime
    last_seen: datetime
    event_ids: tuple[str, ...]


def _parse_metadata_time(value: str) -> datetime:
    parse_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(parse_value).astimezone(timezone.utc)


def _correlation_signal(finding: Finding) -> _CorrelationSignal | None:
    metadata = finding.metadata
    first_seen_raw = metadata.get("first_seen") or metadata.get("event_time")
    last_seen_raw = metadata.get("last_seen") or first_seen_raw
    if not first_seen_raw or not last_seen_raw:
        return None
    try:
        first_seen = _parse_metadata_time(first_seen_raw)
        last_seen = _parse_metadata_time(last_seen_raw)
    except ValueError:
        return None

    event_ids_raw = metadata.get("event_ids") or metadata.get("event_id")
    if not event_ids_raw:
        return None
    event_ids = tuple(
        dict.fromkeys(item.strip() for item in event_ids_raw.split(",") if item.strip())
    )
    if not event_ids:
        return None
    return _CorrelationSignal(
        finding=finding,
        first_seen=first_seen,
        last_seen=last_seen,
        event_ids=event_ids,
    )


def _isoformat_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _incident_title(rule_ids: set[str]) -> str:
    if rule_ids == {"CLD-006"}:
        return "Repeated failed API activity"
    if "CLD-010" in rule_ids and rule_ids.intersection({"CLD-008", "CLD-009"}):
        return "Monitoring defenses weakened during persistence activity"
    if "CLD-002" in rule_ids:
        return "Identity protection weakened before control-plane changes"
    return "Correlated cloud control-plane activity"


def _incident_actions(rule_ids: set[str]) -> list[str]:
    actions = [
        "Validate the actor, session context, source IP, and change authorization.",
    ]
    if "CLD-010" in rule_ids:
        actions.append(
            "Restore affected logging or detection controls and verify telemetry continuity."
        )
    if rule_ids.intersection({"CLD-002", "CLD-007", "CLD-008", "CLD-009"}):
        actions.append(
            "Contain the identity, remove unapproved credentials or trust, and restore MFA."
        )
    if "CLD-011" in rule_ids:
        actions.append(
            "Cancel unauthorized key deletion or re-enable the key, then assess dependent data."
        )
    if "CLD-006" in rule_ids:
        actions.append(
            "Review failed API names, error codes, source reputation, and related authentication."
        )
    actions.append("Preserve relevant CloudTrail records and open an incident-response case.")
    return list(dict.fromkeys(actions))


def _incident_id(
    *,
    actor: str,
    source_ip: str,
    first_seen: str,
    last_seen: str,
    rule_ids: list[str],
    event_ids: list[str],
) -> str:
    canonical = json.dumps(
        {
            "actor": actor,
            "source_ip": source_ip,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "rule_ids": rule_ids,
            "event_ids": event_ids,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12].upper()
    return f"CTI-{digest}"


def _build_incident(
    actor: str,
    source_ip: str,
    signals: list[_CorrelationSignal],
) -> Incident | None:
    rule_ids = sorted({signal.finding.rule_id for signal in signals})
    event_ids = sorted(
        {event_id for signal in signals for event_id in signal.event_ids}
    )
    is_failure_incident = rule_ids == ["CLD-006"] and len(event_ids) >= 2
    is_multi_signal_incident = len(rule_ids) >= 2 and len(event_ids) >= 2
    if not is_failure_incident and not is_multi_signal_incident:
        return None

    first_seen = _isoformat_utc(min(signal.first_seen for signal in signals))
    last_seen = _isoformat_utc(max(signal.last_seen for signal in signals))
    rule_id_set = set(rule_ids)
    severity = min(
        (signal.finding.severity for signal in signals),
        key=severity_rank,
    )
    resources = sorted(
        {
            f"{signal.finding.resource_type}/{signal.finding.resource_id}"
            for signal in signals
        }
    )
    references = sorted(
        {
            reference
            for signal in signals
            for reference in signal.finding.references
        }
    )
    confidence = "high" if len(rule_ids) >= 3 else "medium"
    signal_label = "signal" if len(signals) == 1 else "signals"
    rule_label = "rule" if len(rule_ids) == 1 else "rules"
    summary = (
        f"{actor} generated {len(signals)} suspicious {signal_label} across "
        f"{len(rule_ids)} {rule_label} from {source_ip} between {first_seen} and "
        f"{last_seen}: {', '.join(rule_ids)}."
    )
    return Incident(
        incident_id=_incident_id(
            actor=actor,
            source_ip=source_ip,
            first_seen=first_seen,
            last_seen=last_seen,
            rule_ids=rule_ids,
            event_ids=event_ids,
        ),
        severity=severity,
        confidence=confidence,
        module="cloudtrail",
        category="correlated-activity",
        title=_incident_title(rule_id_set),
        actor=actor,
        source_ip=source_ip,
        first_seen=first_seen,
        last_seen=last_seen,
        event_count=len(event_ids),
        finding_count=len(signals),
        rule_ids=rule_ids,
        event_ids=event_ids,
        resources=resources,
        summary=summary,
        recommended_actions=_incident_actions(rule_id_set),
        references=references,
    )


def correlate_incidents(
    findings: list[Finding],
    *,
    window_minutes: int = DEFAULT_CORRELATION_WINDOW_MINUTES,
) -> list[Incident]:
    groups: dict[tuple[str, str], list[_CorrelationSignal]] = defaultdict(list)
    for finding in findings:
        signal = _correlation_signal(finding)
        actor = finding.metadata.get("actor")
        source_ip = finding.metadata.get("source_ip")
        if (
            signal is not None
            and actor
            and source_ip
            and actor != "unknown-actor"
            and source_ip != "unknown-source"
        ):
            groups[(actor, source_ip)].append(signal)

    incidents: list[Incident] = []
    window = timedelta(minutes=window_minutes)
    for (actor, source_ip), group_signals in groups.items():
        ordered = sorted(
            group_signals,
            key=lambda item: (
                item.first_seen,
                item.last_seen,
                item.finding.rule_id,
                item.finding.resource_id,
            ),
        )
        cluster: list[_CorrelationSignal] = []
        anchor: datetime | None = None
        for signal in ordered:
            if anchor is None or signal.first_seen - anchor <= window:
                cluster.append(signal)
                anchor = anchor or signal.first_seen
                continue
            incident = _build_incident(actor, source_ip, cluster)
            if incident is not None:
                incidents.append(incident)
            cluster = [signal]
            anchor = signal.first_seen

        if cluster:
            incident = _build_incident(actor, source_ip, cluster)
            if incident is not None:
                incidents.append(incident)

    return sort_incidents(incidents)
