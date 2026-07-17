"""Validate and attach optional network reachability assessments."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cloud_analysis import SkippedEvidence

SCHEMA_VERSION = "1.0"
REACHABILITY_METHODS = frozenset(
    {
        "aws-network-access-analyzer",
        "aws-reachability-analyzer",
        "manual-topology-review",
        "other",
    }
)
REACHABILITY_STATUSES = frozenset({"reachable", "not_reachable", "inconclusive"})


@dataclass(frozen=True)
class NetworkReachabilityResult:
    """Network environment enriched with supplied path assessments."""

    environment: dict[str, Any]
    warnings: tuple[str, ...]
    skipped_evidence: tuple[SkippedEvidence, ...] = ()


def _load_json_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("Network reachability context must contain a JSON object.")
    return payload


def _only_keys(payload: dict[str, Any], allowed: set[str], context: str) -> None:
    unexpected = sorted(set(payload).difference(allowed))
    if unexpected:
        raise ValueError(f"{context} contains unsupported fields: {', '.join(unexpected)}.")


def _required_string(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} is missing a non-empty {key} value.")
    return value


def _string_list(
    payload: dict[str, Any],
    key: str,
    context: str,
    *,
    required: bool,
) -> list[str]:
    if key not in payload and not required:
        return []
    value = payload.get(key)
    if (
        not isinstance(value, list)
        or (required and not value)
        or not all(isinstance(item, str) and item for item in value)
    ):
        qualifier = "non-empty " if required else ""
        raise ValueError(f"{context} field {key} must be a {qualifier}list of strings.")
    if len(value) != len(set(value)):
        raise ValueError(f"{context} field {key} must not contain duplicate values.")
    return list(value)


def _direction(payload: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{context} field {key} must be an object.")
    direction_context = f"{context} {key} assessment"
    _only_keys(
        value,
        {"status", "scope", "evidence", "resource_ids"},
        direction_context,
    )
    status = _required_string(value, "status", direction_context)
    if status not in REACHABILITY_STATUSES:
        allowed = ", ".join(sorted(REACHABILITY_STATUSES))
        raise ValueError(f"{direction_context} status must be one of: {allowed}.")
    return {
        "status": status,
        "scope": _required_string(value, "scope", direction_context),
        "evidence": _string_list(value, "evidence", direction_context, required=True),
        "resource_ids": _string_list(
            value,
            "resource_ids",
            direction_context,
            required=False,
        ),
    }


def _observed_at(payload: dict[str, Any], context: str) -> str:
    value = _required_string(payload, "observed_at", context)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{context} observed_at must be an RFC 3339 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{context} observed_at must include a UTC offset.")
    return value


def normalize_network_reachability_context(
    payload: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Validate a reachability context payload and index it by security group."""

    _only_keys(payload, {"schema_version", "security_groups"}, "Reachability context")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            "Network reachability context uses an unsupported schema version; "
            f"expected {SCHEMA_VERSION}."
        )
    groups = payload.get("security_groups")
    if not isinstance(groups, list) or not groups or not all(
        isinstance(item, dict) for item in groups
    ):
        raise ValueError(
            "Network reachability context security_groups must be a non-empty list of objects."
        )

    assessments: dict[str, dict[str, Any]] = {}
    for index, group in enumerate(groups):
        context = f"Reachability context entry {index + 1}"
        _only_keys(
            group,
            {"group_id", "method", "observed_at", "ingress", "egress"},
            context,
        )
        group_id = _required_string(group, "group_id", context)
        if group_id in assessments:
            raise ValueError(
                f"Network reachability context contains duplicate security group {group_id}."
            )
        method = _required_string(group, "method", context)
        if method not in REACHABILITY_METHODS:
            allowed = ", ".join(sorted(REACHABILITY_METHODS))
            raise ValueError(f"{context} method must be one of: {allowed}.")
        assessments[group_id] = {
            "method": method,
            "observed_at": _observed_at(group, context),
            "ingress": _direction(group, "ingress", context),
            "egress": _direction(group, "egress", context),
        }
    return assessments


def apply_network_reachability_context(
    environment: dict[str, Any],
    assessments: dict[str, dict[str, Any]],
) -> NetworkReachabilityResult:
    """Attach validated assessments without mutating the source environment."""

    groups = environment.get("security_groups")
    if not isinstance(groups, list) or not all(isinstance(group, dict) for group in groups):
        raise ValueError("Network environment security_groups must be a list of objects.")

    group_ids: list[str] = []
    for group in groups:
        group_id = group.get("id")
        if not isinstance(group_id, str) or not group_id:
            raise ValueError("Each network security group must have a non-empty id.")
        if group_id in group_ids:
            raise ValueError(f"Network environment contains duplicate security group {group_id}.")
        group_ids.append(group_id)

    unknown_ids = sorted(set(assessments).difference(group_ids))
    if unknown_ids:
        raise ValueError(
            "Network reachability context references security groups absent from the "
            f"environment: {', '.join(unknown_ids)}."
        )

    enriched = copy.deepcopy(environment)
    for group in enriched["security_groups"]:
        group_id = group["id"]
        group.pop("reachability", None)
        if group_id in assessments:
            group["reachability"] = copy.deepcopy(assessments[group_id])

    missing_ids = sorted(set(group_ids).difference(assessments))
    warnings: list[str] = []
    if missing_ids:
        warnings.append(
            "Reachability context was not supplied for "
            f"{len(missing_ids)} security group(s): {', '.join(missing_ids)}. "
            "Their findings remain configuration-only."
        )
    return NetworkReachabilityResult(
        environment=enriched,
        warnings=tuple(warnings),
    )


def load_network_reachability_context(path: Path) -> dict[str, dict[str, Any]]:
    """Load and validate a versioned network reachability context file."""

    return normalize_network_reachability_context(_load_json_object(path))
