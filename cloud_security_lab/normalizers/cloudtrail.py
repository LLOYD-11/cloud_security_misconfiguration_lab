"""Normalize native AWS CloudTrail log files into the detector contract."""

from __future__ import annotations

import gzip
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Sequence

from cloud_analysis import SkippedEvidence
from cloud_inputs import (
    JsonBudget,
    enforce_collection_limit,
    enforce_input_file_count,
    load_bounded_json,
    validate_analysis_input_limits,
    validate_json_value_limits,
)

ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
EVENT_ID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
EVENT_VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)$")
ARN_ACCOUNT_PATTERN = re.compile(r"^arn:[^:]+:[^:]*:[^:]*:(\d{12}):")


@dataclass(frozen=True)
class CloudTrailNormalizationResult:
    """Normalized CloudTrail input plus non-fatal evidence-quality warnings."""

    environment: dict[str, Any]
    warnings: tuple[str, ...]
    skipped_evidence: tuple[SkippedEvidence, ...] = ()


def _load_json_object(
    path: Path,
    *,
    budget: JsonBudget | None = None,
) -> dict[str, Any]:
    try:
        payload = load_bounded_json(
            path,
            label=f"CloudTrail file {path}",
            allow_gzip=True,
            budget=budget,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"CloudTrail file {path} does not contain valid JSON: {exc.msg}."
        ) from exc
    except UnicodeDecodeError as exc:
        if path.suffix.lower() == ".gz":
            raise ValueError(
                f"CloudTrail file {path} is not valid gzip-compressed JSON."
            ) from exc
        raise ValueError(f"CloudTrail file {path} is not valid UTF-8 JSON.") from exc
    except (gzip.BadGzipFile, EOFError) as exc:
        raise ValueError(
            f"CloudTrail file {path} is not valid gzip-compressed JSON."
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError(f"CloudTrail file {path} must contain a JSON object.")
    return payload


def _required_string(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} is missing a non-empty {key} value.")
    return value


def _optional_string(payload: dict[str, Any], key: str, context: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} field {key} must be a non-empty string when present.")
    return value


def _records(payload: dict[str, Any], context: str) -> list[dict[str, Any]]:
    records = payload.get("Records")
    if not isinstance(records, list) or not all(isinstance(record, dict) for record in records):
        raise ValueError(f"{context} field Records must be a list of objects.")
    if not records:
        raise ValueError(f"{context} field Records must contain at least one event.")
    return records


def _validate_event_version(event: dict[str, Any], context: str) -> None:
    version = _required_string(event, "eventVersion", context)
    match = EVENT_VERSION_PATTERN.fullmatch(version)
    if match is None:
        raise ValueError(f"{context} eventVersion must use major.minor numeric form.")
    if int(match.group(1)) != 1:
        raise ValueError(f"{context} uses unsupported CloudTrail eventVersion {version}.")


def _validate_event_time(event: dict[str, Any], context: str) -> None:
    raw_time = _required_string(event, "eventTime", context)
    parse_value = raw_time[:-1] + "+00:00" if raw_time.endswith("Z") else raw_time
    try:
        parsed = datetime.fromisoformat(parse_value)
    except ValueError as exc:
        raise ValueError(f"{context} eventTime must be an ISO 8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{context} eventTime must use UTC (Z or +00:00).")


def _validate_optional_objects(event: dict[str, Any], context: str) -> None:
    for key in ("requestParameters", "responseElements", "additionalEventData"):
        value = event.get(key)
        if value is not None and not isinstance(value, dict):
            raise ValueError(f"{context} field {key} must be an object or null.")


def _validate_optional_metadata(event: dict[str, Any], context: str) -> None:
    for key in ("userAgent", "requestID", "eventType", "eventCategory"):
        _optional_string(event, key, context)
    event_category = event.get("eventCategory")
    if event_category is not None and event_category not in {
        "Management",
        "Data",
        "NetworkActivity",
    }:
        raise ValueError(f"{context} uses unsupported eventCategory {event_category}.")
    for key in ("readOnly", "managementEvent"):
        value = event.get(key)
        if value is not None and not isinstance(value, bool):
            raise ValueError(f"{context} field {key} must be a boolean when present.")


def _identity(event: dict[str, Any], context: str) -> dict[str, Any]:
    identity = event.get("userIdentity")
    if not isinstance(identity, dict):
        raise ValueError(f"{context} field userIdentity must be an object.")
    _required_string(identity, "type", f"{context} userIdentity")
    for key in ("principalId", "userName"):
        _optional_string(identity, key, f"{context} userIdentity")
    identity_arn = _optional_string(identity, "arn", f"{context} userIdentity")
    account_id = _optional_string(identity, "accountId", f"{context} userIdentity")
    if account_id is not None and not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise ValueError(f"{context} userIdentity accountId must be a 12-digit AWS account ID.")
    if account_id is not None and identity_arn is not None:
        arn_match = ARN_ACCOUNT_PATTERN.match(identity_arn)
        if arn_match is not None and arn_match.group(1) != account_id:
            raise ValueError(
                f"{context} userIdentity accountId does not match its ARN account."
            )
    return identity


def _event_account_id(
    event: dict[str, Any],
    identity: dict[str, Any],
    context: str,
) -> tuple[str, bool]:
    recipient_account_id = _optional_string(event, "recipientAccountId", context)
    if recipient_account_id is not None:
        if not ACCOUNT_ID_PATTERN.fullmatch(recipient_account_id):
            raise ValueError(f"{context} recipientAccountId must be a 12-digit AWS account ID.")
        return recipient_account_id, False

    identity_account_id = identity.get("accountId")
    if isinstance(identity_account_id, str):
        return identity_account_id, True
    identity_arn = identity.get("arn")
    if isinstance(identity_arn, str):
        match = ARN_ACCOUNT_PATTERN.match(identity_arn)
        if match is not None:
            return match.group(1), True
    raise ValueError(
        f"{context} has no recipientAccountId or usable userIdentity account context."
    )


def _normalized_event(
    event: dict[str, Any],
    context: str,
) -> tuple[dict[str, Any], str, bool]:
    _validate_event_version(event, context)
    _validate_event_time(event, context)
    for key in ("eventSource", "eventName", "awsRegion", "sourceIPAddress"):
        _required_string(event, key, context)
    event_id = _required_string(event, "eventID", context)
    if not EVENT_ID_PATTERN.fullmatch(event_id):
        raise ValueError(f"{context} eventID must be a CloudTrail GUID.")
    identity = _identity(event, context)
    _validate_optional_objects(event, context)
    _validate_optional_metadata(event, context)
    _optional_string(event, "errorCode", context)
    error_message = event.get("errorMessage")
    if error_message is not None and not isinstance(error_message, str):
        raise ValueError(f"{context} field errorMessage must be a string when present.")
    account_id, used_fallback = _event_account_id(event, identity, context)
    return dict(event), account_id, used_fallback


def normalize_aws_cloudtrail_environment(
    log_files: Sequence[dict[str, Any]],
) -> CloudTrailNormalizationResult:
    """Merge native CloudTrail Records payloads into one detector environment."""

    if not log_files:
        raise ValueError("At least one native CloudTrail log file is required.")
    enforce_input_file_count(
        len(log_files),
        label="CloudTrail input set",
    )
    node_budget = JsonBudget("CloudTrail input set")
    for file_index, payload in enumerate(log_files):
        validate_json_value_limits(
            payload,
            label=f"CloudTrail log file {file_index + 1}",
            budget=node_budget,
        )

    events: list[dict[str, Any]] = []
    events_by_id: dict[str, dict[str, Any]] = {}
    account_ids: set[str] = set()
    duplicate_count = 0
    duplicate_event_ids: set[str] = set()
    account_fallback_count = 0
    record_count = 0
    for file_index, payload in enumerate(log_files):
        file_context = f"CloudTrail log file {file_index + 1}"
        records = _records(payload, file_context)
        record_count += len(records)
        enforce_collection_limit(
            record_count,
            label="CloudTrail event input",
        )
        for record_index, record in enumerate(records):
            context = f"{file_context} record {record_index + 1}"
            event, account_id, used_fallback = _normalized_event(record, context)
            event_id = str(event["eventID"])
            existing = events_by_id.get(event_id)
            if existing is not None:
                if existing != event:
                    raise ValueError(
                        f"{context} conflicts with another record using eventID {event_id}."
                    )
                duplicate_count += 1
                duplicate_event_ids.add(event_id)
                continue
            events_by_id[event_id] = event
            events.append(event)
            account_ids.add(account_id)
            if used_fallback:
                account_fallback_count += 1

    if len(account_ids) != 1:
        raise ValueError(
            "CloudTrail log files contain multiple recipient account IDs; "
            "analyze one account snapshot at a time."
        )

    warnings: list[str] = []
    if duplicate_count:
        warnings.append(
            f"Skipped {duplicate_count} duplicate CloudTrail record(s) with identical eventID values."
        )
    if account_fallback_count:
        warnings.append(
            f"Derived account context from userIdentity for {account_fallback_count} "
            "CloudTrail record(s) without recipientAccountId."
        )
    skipped_evidence: tuple[SkippedEvidence, ...] = ()
    if duplicate_count:
        skipped_evidence = (
            SkippedEvidence(
                code="CLD_DUPLICATE_EVENT",
                evidence_type="cloudtrail-event",
                reason="Identical records sharing an event ID were analyzed once.",
                count=duplicate_count,
                affects_coverage=False,
                resource_ids=sorted(duplicate_event_ids),
            ),
        )
    environment = {
        "account_id": next(iter(account_ids)),
        "events": events,
    }
    validate_analysis_input_limits("cloudtrail", environment)
    return CloudTrailNormalizationResult(
        environment=environment,
        warnings=tuple(warnings),
        skipped_evidence=skipped_evidence,
    )


def load_aws_cloudtrail_environment(
    paths: Sequence[Path],
) -> CloudTrailNormalizationResult:
    """Load and merge native JSON or gzip-compressed CloudTrail log files."""

    if not paths:
        raise ValueError("At least one native CloudTrail log file path is required.")
    enforce_input_file_count(paths, label="CloudTrail input set")
    seen_paths: set[Path] = set()
    payloads: list[dict[str, Any]] = []
    budget = JsonBudget("CloudTrail input set")
    for path in paths:
        resolved = path.resolve()
        if resolved in seen_paths:
            raise ValueError(f"CloudTrail input path was provided more than once: {path}.")
        seen_paths.add(resolved)
        payloads.append(_load_json_object(path, budget=budget))
    return normalize_aws_cloudtrail_environment(payloads)
