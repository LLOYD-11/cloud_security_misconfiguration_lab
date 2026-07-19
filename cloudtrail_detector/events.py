"""Shared CloudTrail event-boundary helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class CloudTrailEventDeduplication:
    """Unique events plus evidence about identical records that were skipped."""

    events: tuple[dict[str, Any], ...]
    duplicate_count: int
    duplicate_event_ids: tuple[str, ...]


def deduplicate_cloudtrail_events(
    raw_events: Iterable[Any],
) -> CloudTrailEventDeduplication:
    """Analyze identical IDs once and reject ambiguous conflicting records."""

    events: list[dict[str, Any]] = []
    events_by_id: dict[str, dict[str, Any]] = {}
    duplicate_count = 0
    duplicate_event_ids: set[str] = set()

    for event in raw_events:
        if not isinstance(event, dict):
            continue
        event_id = event.get("eventID")
        if not event_id:
            events.append(event)
            continue

        normalized_event_id = str(event_id)
        existing = events_by_id.get(normalized_event_id)
        if existing is None:
            events_by_id[normalized_event_id] = event
            events.append(event)
            continue
        if existing != event:
            raise ValueError(
                f"Conflicting CloudTrail events share eventID {normalized_event_id!r}."
            )

        duplicate_count += 1
        duplicate_event_ids.add(normalized_event_id)

    return CloudTrailEventDeduplication(
        events=tuple(events),
        duplicate_count=duplicate_count,
        duplicate_event_ids=tuple(sorted(duplicate_event_ids)),
    )
