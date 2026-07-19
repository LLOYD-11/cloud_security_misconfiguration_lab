"""Build module-neutral analysis coverage summaries."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from cloud_analysis import AnalysisSummary, ResourceCoverage, SkippedEvidence
from cloud_security_lab import __version__
from cloudtrail_detector.events import deduplicate_cloudtrail_events


def _objects(environment: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = environment.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"Analysis summary expected {key} to be a list.")
    return [item for item in value if isinstance(item, dict)]


def _issue(
    code: str,
    evidence_type: str,
    reason: str,
    resource_ids: Iterable[str],
    *,
    affects_coverage: bool = True,
    count: int | None = None,
) -> SkippedEvidence:
    unique_ids = sorted(set(resource_ids))
    return SkippedEvidence(
        code=code,
        evidence_type=evidence_type,
        reason=reason,
        count=count if count is not None else len(unique_ids),
        affects_coverage=affects_coverage,
        resource_ids=unique_ids,
    )


def _iam_skipped_evidence(environment: dict[str, Any]) -> list[SkippedEvidence]:
    skipped: list[SkippedEvidence] = []
    users = _objects(environment, "users")
    groups = _objects(environment, "groups")
    roles = _objects(environment, "roles")

    if "groups" not in environment:
        skipped.append(
            _issue(
                "IAM_GROUP_INVENTORY_ABSENT",
                "iam-group-inventory",
                "No group inventory was supplied, so inherited group permissions were not evaluated.",
                ["groups"],
            )
        )
    known_groups = {
        str(group.get("name"))
        for group in groups
        if isinstance(group.get("name"), str) and group.get("name")
    }
    missing_group_refs = {
        f"{user.get('name', 'unknown-user')}->{group_name}"
        for user in users
        for group_name in user.get("groups", [])
        if isinstance(group_name, str) and group_name not in known_groups
    }
    if missing_group_refs:
        skipped.append(
            _issue(
                "IAM_GROUP_DETAIL_ABSENT",
                "iam-group-detail",
                "Referenced group details were absent, so their inherited policies were not evaluated.",
                missing_group_refs,
            )
        )

    if not isinstance(environment.get("root_account"), dict):
        skipped.append(
            _issue(
                "IAM_ROOT_CREDENTIAL_EVIDENCE_ABSENT",
                "root-credential-posture",
                "Root password, MFA, and access-key posture were not supplied.",
                ["root"],
            )
        )

    missing_password_status = {
        str(user.get("name", "unknown-user"))
        for user in users
        if "password_enabled" not in user
    }
    if missing_password_status:
        skipped.append(
            _issue(
                "IAM_CONSOLE_PASSWORD_STATUS_ABSENT",
                "console-password-status",
                "Console-password status was absent and the compatibility path assumed it was enabled.",
                missing_password_status,
            )
        )

    missing_password_usage = {
        str(user.get("name", "unknown-user"))
        for user in users
        if user.get("password_enabled") is True
        and "password_last_used_days" not in user
    }
    if missing_password_usage:
        skipped.append(
            _issue(
                "IAM_PASSWORD_USAGE_ABSENT",
                "console-password-usage",
                "Password last-used evidence was absent, so stale-password analysis was skipped.",
                missing_password_usage,
            )
        )

    missing_key_usage: set[str] = set()
    for user in users:
        username = str(user.get("name", "unknown-user"))
        access_keys = user.get("access_keys", [])
        if not isinstance(access_keys, list):
            continue
        for index, key in enumerate(access_keys):
            if (
                isinstance(key, dict)
                and str(key.get("status", "Active")).lower() != "inactive"
                and "last_used_days" not in key
            ):
                key_id = str(key.get("id") or f"key-{index + 1}")
                missing_key_usage.add(f"{username}/{key_id}")
    if missing_key_usage:
        skipped.append(
            _issue(
                "IAM_ACCESS_KEY_USAGE_ABSENT",
                "access-key-usage",
                "Access-key last-used evidence was absent, so stale-key usage analysis was skipped.",
                missing_key_usage,
            )
        )

    unavailable_boundaries = {
        f"{principal_type}/{principal.get('name', 'unknown')}"
        for principal_type, principals in (("user", users), ("role", roles))
        for principal in principals
        if isinstance(principal.get("permissions_boundary"), dict)
        and principal["permissions_boundary"].get("document_available") is False
    }
    if unavailable_boundaries:
        skipped.append(
            _issue(
                "IAM_PERMISSIONS_BOUNDARY_DOCUMENT_ABSENT",
                "permissions-boundary-document",
                "A referenced permissions-boundary document was absent, so its constraints were not evaluated.",
                unavailable_boundaries,
            )
        )
    return skipped


def _storage_skipped_evidence(
    environment: dict[str, Any],
) -> list[SkippedEvidence]:
    missing_ownership = {
        str(bucket.get("name", "unknown-bucket"))
        for bucket in _objects(environment, "buckets")
        if "object_ownership" not in bucket
    }
    if not missing_ownership:
        return []
    return [
        _issue(
            "STO_OBJECT_OWNERSHIP_ABSENT",
            "s3-object-ownership",
            "Object Ownership evidence was absent, so ACL disablement could not be confirmed.",
            missing_ownership,
        )
    ]


def _network_skipped_evidence(
    environment: dict[str, Any],
) -> list[SkippedEvidence]:
    groups = _objects(environment, "security_groups")
    unresolved: dict[str, set[str]] = defaultdict(set)
    missing_reachability: set[str] = set()
    for group in groups:
        group_id = str(group.get("id", group.get("name", "unknown-security-group")))
        if not isinstance(group.get("reachability"), dict):
            missing_reachability.add(group_id)
        for direction, key in (("ingress", "inbound_rules"), ("egress", "outbound_rules")):
            rules = group.get(key, [])
            if not isinstance(rules, list):
                continue
            for index, rule in enumerate(rules):
                if not isinstance(rule, dict) or "cidr" in rule:
                    continue
                peer_type = str(rule.get("peer_type", "unknown-peer"))
                unresolved[peer_type].add(f"{group_id}:{direction}:{index + 1}")

    skipped: list[SkippedEvidence] = []
    for peer_type, resource_ids in sorted(unresolved.items()):
        code_label = peer_type.upper().replace("-", "_")
        evidence_label = peer_type.replace("_", "-")
        skipped.append(
            _issue(
                f"NET_{code_label}_TARGET_UNRESOLVED",
                f"network-{evidence_label}-target",
                (
                    f"{evidence_label.replace('-', ' ')} targets were preserved but not "
                    "expanded into CIDRs or evaluated for public exposure."
                ),
                resource_ids,
            )
        )
    if missing_reachability:
        skipped.append(
            _issue(
                "NET_REACHABILITY_NOT_ASSESSED",
                "network-reachability-assessment",
                "No end-to-end reachability assessment was supplied; configuration analysis still ran.",
                missing_reachability,
            )
        )
    return skipped


def _cloudtrail_skipped_evidence(
    environment: dict[str, Any],
) -> list[SkippedEvidence]:
    raw_events = environment.get("events", [])
    if not isinstance(raw_events, list):
        raise ValueError("Analysis summary expected events to be a list.")

    skipped: list[SkippedEvidence] = []
    invalid_indexes = [
        f"event-{index + 1}"
        for index, event in enumerate(raw_events)
        if not isinstance(event, dict)
    ]
    if invalid_indexes:
        skipped.append(
            _issue(
                "CLD_EVENT_NOT_OBJECT",
                "cloudtrail-event",
                "Non-object event entries were ignored by the detector.",
                invalid_indexes,
            )
        )

    deduplication = deduplicate_cloudtrail_events(raw_events)
    if deduplication.duplicate_count:
        skipped.append(
            _issue(
                "CLD_DUPLICATE_EVENT",
                "cloudtrail-event",
                "Identical records sharing an event ID were analyzed once.",
                deduplication.duplicate_event_ids,
                affects_coverage=False,
                count=deduplication.duplicate_count,
            )
        )

    missing_ids = {
        f"event-{index + 1}"
        for index, event in enumerate(raw_events)
        if isinstance(event, dict) and not event.get("eventID")
    }
    if missing_ids:
        skipped.append(
            _issue(
                "CLD_EVENT_ID_ABSENT",
                "cloudtrail-event-id",
                "Event IDs were absent, limiting duplicate detection and stable incident evidence.",
                missing_ids,
            )
        )

    missing_mfa_usage = set()
    for index, event in enumerate(raw_events):
        if not isinstance(event, dict) or event.get("eventName") != "ConsoleLogin":
            continue
        identity = event.get("userIdentity")
        if not isinstance(identity, dict) or str(identity.get("type", "")).lower() != "iamuser":
            continue
        additional = event.get("additionalEventData")
        if not isinstance(additional, dict) or "MFAUsed" not in additional:
            missing_mfa_usage.add(str(event.get("eventID") or f"event-{index + 1}"))
    if missing_mfa_usage:
        skipped.append(
            _issue(
                "CLD_CONSOLE_LOGIN_MFA_EVIDENCE_ABSENT",
                "console-login-mfa-evidence",
                "IAM user ConsoleLogin events lacked MFAUsed evidence, so password-only login detection was skipped.",
                missing_mfa_usage,
            )
        )
    return skipped


def _merge_skipped_evidence(
    skipped_evidence: Iterable[SkippedEvidence],
) -> list[SkippedEvidence]:
    grouped: dict[tuple[str, str, str, bool], dict[str, Any]] = {}
    for item in skipped_evidence:
        key = (
            item.code,
            item.evidence_type,
            item.reason,
            item.affects_coverage,
        )
        group = grouped.setdefault(key, {"count": 0, "resource_ids": set()})
        group["count"] += item.count
        group["resource_ids"].update(item.resource_ids)

    merged = [
        SkippedEvidence(
            code=code,
            evidence_type=evidence_type,
            reason=reason,
            count=values["count"],
            affects_coverage=affects_coverage,
            resource_ids=sorted(values["resource_ids"]),
        )
        for (
            code,
            evidence_type,
            reason,
            affects_coverage,
        ), values in grouped.items()
    ]
    return sorted(
        merged,
        key=lambda item: (item.code, item.evidence_type, tuple(item.resource_ids)),
    )


def _resource_coverage(
    module: str,
    environment: dict[str, Any],
    skipped_evidence: list[SkippedEvidence],
) -> list[ResourceCoverage]:
    if module == "iam":
        users = _objects(environment, "users")
        groups = _objects(environment, "groups")
        roles = _objects(environment, "roles")
        known_groups = {
            str(group.get("name"))
            for group in groups
            if isinstance(group.get("name"), str) and group.get("name")
        }
        missing_groups = {
            group_name
            for user in users
            for group_name in user.get("groups", [])
            if isinstance(group_name, str) and group_name not in known_groups
        }
        skipped_users = sum(
            item.count
            for item in skipped_evidence
            if item.code == "IAM_IDENTITY_DETAIL_ABSENT"
        )
        root_evaluated = int(isinstance(environment.get("root_account"), dict))
        coverage = (
            ResourceCoverage(
                "group",
                len(groups) + len(missing_groups),
                len(groups),
                len(missing_groups),
            ),
            ResourceCoverage("role", len(roles), len(roles), 0),
            ResourceCoverage("root-account", 1, root_evaluated, 1 - root_evaluated),
            ResourceCoverage(
                "user",
                len(users) + skipped_users,
                len(users),
                skipped_users,
            ),
        )
        return list(coverage)
    if module == "storage":
        count = len(_objects(environment, "buckets"))
        return [ResourceCoverage("bucket", count, count, 0)]
    if module == "network":
        count = len(_objects(environment, "security_groups"))
        return [ResourceCoverage("security-group", count, count, 0)]
    if module == "cloudtrail":
        raw_events = environment.get("events", [])
        if not isinstance(raw_events, list):
            raise ValueError("Analysis summary expected events to be a list.")
        evaluated_count = len(deduplicate_cloudtrail_events(raw_events).events)
        skipped_count = sum(
            item.count
            for item in skipped_evidence
            if item.code
            in {
                "CLD_DUPLICATE_EVENT",
                "CLD_EVENT_NOT_OBJECT",
            }
        )
        return [
            ResourceCoverage(
                "event",
                evaluated_count + skipped_count,
                evaluated_count,
                skipped_count,
            )
        ]
    raise ValueError(f"Unsupported analyzer module: {module}")


def build_analysis_summary(
    *,
    module: str,
    environment: dict[str, Any],
    input_format: str,
    input_file_count: int,
    finding_count: int,
    incident_count: int = 0,
    parameters: dict[str, str] | None = None,
    warnings: Iterable[str] = (),
    skipped_evidence: Iterable[SkippedEvidence] = (),
) -> AnalysisSummary:
    """Build one deterministic summary from normalized evidence and analyzer results."""

    inferred_builders = {
        "iam": _iam_skipped_evidence,
        "storage": _storage_skipped_evidence,
        "network": _network_skipped_evidence,
        "cloudtrail": _cloudtrail_skipped_evidence,
    }
    try:
        inferred = inferred_builders[module](environment)
    except KeyError as exc:
        raise ValueError(f"Unsupported analyzer module: {module}") from exc
    merged_skips = _merge_skipped_evidence([*skipped_evidence, *inferred])
    resources = _resource_coverage(module, environment, merged_skips)
    evaluated_count = sum(item.evaluated_count for item in resources)
    coverage_status = (
        "empty"
        if evaluated_count == 0
        else (
            "partial"
            if any(item.affects_coverage for item in merged_skips)
            else "complete"
        )
    )
    return AnalysisSummary(
        module=module,
        analyzer_version=__version__,
        input_format=input_format,
        input_file_count=input_file_count,
        coverage_status=coverage_status,
        finding_count=finding_count,
        incident_count=incident_count,
        parameters=dict(sorted((parameters or {}).items())),
        resource_coverage=resources,
        skipped_evidence=merged_skips,
        warnings=list(dict.fromkeys(warnings)),
    )
