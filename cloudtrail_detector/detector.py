"""Detect suspicious activity in offline CloudTrail-style event data."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cloud_findings import (
    EvidenceReference,
    Finding,
    sort_findings,
    with_findings_context,
    write_findings,
)
from cloud_incidents import Incident, write_incidents
from cloud_rules import validate_rule_emission
from cloudtrail_detector.correlation import (
    DEFAULT_CORRELATION_WINDOW_MINUTES,
    correlate_incidents,
)

REF_AWS_CLOUDTRAIL = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html"
REF_AWS_CLOUDTRAIL_RECORD = (
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
    "cloudtrail-event-reference-record-contents.html"
)
REF_AWS_CLOUDTRAIL_SECURITY = (
    "https://docs.aws.amazon.com/prescriptive-guidance/latest/"
    "logging-monitoring-for-application-owners/cloudtrail.html"
)
REF_AWS_IAM_BEST_PRACTICES = "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
REF_AWS_IAM_CREATE_ACCESS_KEY = (
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html"
)
REF_AWS_IAM_UPDATE_TRUST = (
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html"
)
REF_AWS_S3_BUCKET_POLICIES = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html"
REF_AWS_GUARDDUTY_DELETE = (
    "https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html"
)
REF_AWS_KMS_DELETE = (
    "https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html"
)
REF_MITRE_CLOUD_ACCOUNTS = "https://attack.mitre.org/techniques/T1078/004/"
REF_MITRE_ACCOUNT_MANIPULATION = "https://attack.mitre.org/techniques/T1098/"
REF_MITRE_ADDITIONAL_CREDENTIALS = "https://attack.mitre.org/techniques/T1098/001/"
REF_MITRE_ADDITIONAL_ROLES = "https://attack.mitre.org/techniques/T1098/003/"
REF_MITRE_DATA_MANIPULATION = "https://attack.mitre.org/techniques/T1565/"
REF_MITRE_INFRA_MODIFY = "https://attack.mitre.org/techniques/T1578/005/"
REF_MITRE_BRUTE_FORCE = "https://attack.mitre.org/techniques/T1110/"
REF_MITRE_DISABLE_TOOLS = "https://attack.mitre.org/techniques/T1685/"
REF_MITRE_DISABLE_CLOUD_LOG = "https://attack.mitre.org/techniques/T1685/002/"
REF_MITRE_DATA_DESTRUCTION = "https://attack.mitre.org/techniques/T1485/"
ARN_ACCOUNT_PATTERN = re.compile(r"^arn:[^:]+:[^:]*:[^:]*:(\d{12}):")

MFA_DISABLE_EVENTS = {"DeactivateMFADevice", "DeleteVirtualMFADevice"}
CONSOLE_LOGIN_EVENTS = {"ConsoleLogin"}
SECURITY_GROUP_CHANGE_EVENTS = {
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
}
BUCKET_POLICY_CHANGE_EVENTS = {
    "PutBucketPolicy",
    "PutBucketAcl",
    "DeletePublicAccessBlock",
}
IAM_POLICY_CHANGE_EVENTS = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "CreatePolicy",
    "CreatePolicyVersion",
    "PutUserPolicy",
    "PutRolePolicy",
    "SetDefaultPolicyVersion",
}
CREDENTIAL_CREATION_EVENTS = {
    "CreateAccessKey",
    "CreateLoginProfile",
    "CreateServiceSpecificCredential",
    "UploadSSHPublicKey",
    "UploadSigningCertificate",
}
MONITORING_DISABLE_EVENTS = {
    "DeleteConfigurationRecorder",
    "DeleteDeliveryChannel",
    "DeleteDetector",
    "DeleteFlowLogs",
    "DeleteTrail",
    "DisableSecurityHub",
    "StopConfigurationRecorder",
    "StopLogging",
}
KMS_DISRUPTION_EVENTS = {"DisableKey", "ScheduleKeyDeletion"}
ROLE_TRUST_CHANGE_EVENTS = {"UpdateAssumeRolePolicy"}
UPDATE_DETECTOR_EVENTS = {"UpdateDetector"}
EVENT_SOURCES = {
    "cloudtrail.amazonaws.com": {
        "DeleteTrail",
        "StopLogging",
    },
    "config.amazonaws.com": {
        "DeleteConfigurationRecorder",
        "DeleteDeliveryChannel",
        "StopConfigurationRecorder",
    },
    "ec2.amazonaws.com": {
        *SECURITY_GROUP_CHANGE_EVENTS,
        "DeleteFlowLogs",
    },
    "guardduty.amazonaws.com": {
        "DeleteDetector",
        *UPDATE_DETECTOR_EVENTS,
    },
    "iam.amazonaws.com": {
        *CREDENTIAL_CREATION_EVENTS,
        *IAM_POLICY_CHANGE_EVENTS,
        *MFA_DISABLE_EVENTS,
        *ROLE_TRUST_CHANGE_EVENTS,
    },
    "kms.amazonaws.com": KMS_DISRUPTION_EVENTS,
    "s3.amazonaws.com": BUCKET_POLICY_CHANGE_EVENTS,
    "securityhub.amazonaws.com": {"DisableSecurityHub"},
    "signin.amazonaws.com": CONSOLE_LOGIN_EVENTS,
}
EVENT_SOURCE_BY_EVENT_NAME = {
    event_name: event_source
    for event_source, event_names in EVENT_SOURCES.items()
    for event_name in event_names
}


@dataclass(frozen=True)
class CloudTrailAnalysisResult:
    findings: tuple[Finding, ...]
    incidents: tuple[Incident, ...]


_TimedFailureEvent = tuple[datetime, int, dict[str, Any]]


def _actor(event: dict[str, Any]) -> str:
    identity = event.get("userIdentity", {})
    if not isinstance(identity, dict):
        return "unknown-actor"
    session_context = identity.get("sessionContext", {})
    if not isinstance(session_context, dict):
        session_context = {}
    session_issuer = session_context.get("sessionIssuer", {})
    if not isinstance(session_issuer, dict):
        session_issuer = {}
    return str(
        identity.get("userName")
        or session_issuer.get("userName")
        or session_issuer.get("arn")
        or identity.get("arn")
        or identity.get("principalId")
        or identity.get("type")
        or "unknown-actor"
    )


def _event_time(event: dict[str, Any]) -> datetime:
    raw_time = str(event.get("eventTime", "1970-01-01T00:00:00Z"))
    if raw_time.endswith("Z"):
        raw_time = raw_time[:-1] + "+00:00"
    return datetime.fromisoformat(raw_time).astimezone(timezone.utc)


def _event_name(event: dict[str, Any]) -> str:
    return str(event.get("eventName", "unknown-event"))


def _event_matches(
    event: dict[str, Any],
    event_names: set[str],
) -> bool:
    event_name = _event_name(event)
    if event_name not in event_names:
        return False
    expected_source = EVENT_SOURCE_BY_EVENT_NAME[event_name]
    return event.get("eventSource") == expected_source


def _source_ip(event: dict[str, Any]) -> str:
    return str(event.get("sourceIPAddress", "unknown-source"))


def _request_parameters(event: dict[str, Any]) -> dict[str, Any]:
    params = event.get("requestParameters", {})
    return params if isinstance(params, dict) else {}


def _resource_from_params(event: dict[str, Any], keys: list[str]) -> str:
    params = _request_parameters(event)
    for key in keys:
        value = params.get(key)
        if value:
            return str(value)
    return "unknown-resource"


def _event_id(event: dict[str, Any], index: int) -> str:
    return str(event.get("eventID") or f"{_event_name(event)}-{index + 1}")


def _event_succeeded(event: dict[str, Any]) -> bool:
    if event.get("errorCode") or event.get("errorMessage"):
        return False
    if _event_name(event) == "ConsoleLogin":
        response = event.get("responseElements", {})
        if not isinstance(response, dict):
            return False
        return str(response.get("ConsoleLogin", "")).lower() == "success"
    return True


def _event_identity_type(event: dict[str, Any]) -> str:
    identity = event.get("userIdentity", {})
    if not isinstance(identity, dict):
        return "unknown"
    return str(identity.get("type", "unknown"))


def _console_login_without_mfa(event: dict[str, Any]) -> bool:
    if (
        not _event_matches(event, CONSOLE_LOGIN_EVENTS)
        or _event_identity_type(event).lower() != "iamuser"
    ):
        return False
    additional_data = event.get("additionalEventData", {})
    if not isinstance(additional_data, dict):
        return False
    return str(additional_data.get("MFAUsed", "")).lower() == "no"


def _monitoring_was_disabled(event: dict[str, Any]) -> bool:
    if _event_matches(event, MONITORING_DISABLE_EVENTS):
        return True
    if _event_matches(event, UPDATE_DETECTOR_EVENTS):
        return _request_parameters(event).get("enable") is False
    return False


def _monitoring_references(event_name: str) -> list[str]:
    if event_name in {"StopLogging", "DeleteTrail"}:
        return [
            REF_AWS_CLOUDTRAIL_SECURITY,
            REF_MITRE_DISABLE_CLOUD_LOG,
        ]
    if event_name in {"DeleteDetector", "UpdateDetector"}:
        return [
            REF_AWS_GUARDDUTY_DELETE,
            REF_MITRE_DISABLE_TOOLS,
        ]
    return [
        REF_AWS_CLOUDTRAIL,
        REF_MITRE_DISABLE_TOOLS,
    ]


def _event_account_id(event: dict[str, Any]) -> str:
    recipient_account_id = event.get("recipientAccountId")
    if isinstance(recipient_account_id, str) and re.fullmatch(
        r"\d{12}",
        recipient_account_id,
    ):
        return recipient_account_id
    identity = event.get("userIdentity")
    if not isinstance(identity, dict):
        return "unknown"
    identity_account_id = identity.get("accountId")
    if isinstance(identity_account_id, str) and re.fullmatch(
        r"\d{12}",
        identity_account_id,
    ):
        return identity_account_id
    identity_arn = identity.get("arn")
    if isinstance(identity_arn, str):
        match = ARN_ACCOUNT_PATTERN.match(identity_arn)
        if match is not None:
            return match.group(1)
    return "unknown"


def _add_finding(
    findings: list[Finding],
    *,
    severity: str,
    rule_id: str,
    resource_type: str,
    resource_id: str,
    title: str,
    evidence: str,
    impact: str,
    remediation: str,
    references: list[str],
    metadata: dict[str, str] | None = None,
) -> None:
    rule = validate_rule_emission(rule_id, "cloudtrail", severity)
    assert rule is not None
    metadata_values = metadata or {}
    event_ids = metadata_values.get("event_ids") or metadata_values.get("event_id")
    evidence_references = [
        EvidenceReference(type="cloudtrail-event", id=event_id.strip())
        for event_id in sorted(set((event_ids or "").split(",")))
        if event_id.strip()
    ]
    observed_at_value = (
        metadata_values.get("first_seen")
        or metadata_values.get("event_time")
    )
    observed_at = (
        observed_at_value
        if observed_at_value and observed_at_value != "unknown-time"
        else None
    )
    findings.append(
        Finding(
            rule_id=rule_id,
            severity=severity,
            module="cloudtrail",
            category="audit-and-detection",
            resource_type=resource_type,
            resource_id=resource_id,
            title=title,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            references=references,
            metadata=metadata_values,
            confidence=rule.confidence,
            account_id=metadata_values.get("account_id", "unknown"),
            region=metadata_values.get("aws_region", "unknown"),
            observed_at=observed_at,
            evidence_references=evidence_references,
        )
    )


def analyze_single_event(event: dict[str, Any], index: int) -> list[Finding]:
    findings: list[Finding] = []
    if not _event_succeeded(event):
        return findings

    event_name = _event_name(event)
    actor = _actor(event)
    source_ip = _source_ip(event)
    event_time = str(event.get("eventTime", "unknown-time"))
    identity_type = _event_identity_type(event)
    base_metadata = {
        "event_id": _event_id(event, index),
        "event_name": event_name,
        "event_time": event_time,
        "event_source": str(event.get("eventSource", "unknown-source")),
        "aws_region": str(event.get("awsRegion", "unknown-region")),
        "source_ip": source_ip,
        "actor": actor,
        "identity_type": identity_type,
        "user_agent": str(event.get("userAgent", "unknown-agent")),
        "account_id": _event_account_id(event),
    }

    if _event_matches(event, CONSOLE_LOGIN_EVENTS) and identity_type.lower() == "root":
        _add_finding(
            findings,
            severity="critical",
            rule_id="CLD-001",
            resource_type="identity",
            resource_id="root",
            title="Root account console login",
            evidence=f"Root ConsoleLogin event from {source_ip} at {event_time}.",
            impact="Root account use is highly sensitive and may indicate emergency access or account compromise.",
            remediation="Avoid routine root use, confirm the login was authorized, and require MFA on the root account.",
            references=[REF_AWS_CLOUDTRAIL, REF_AWS_IAM_BEST_PRACTICES, REF_MITRE_CLOUD_ACCOUNTS],
            metadata=base_metadata,
        )

    if _event_matches(event, MFA_DISABLE_EVENTS):
        target_user = _resource_from_params(event, ["userName", "serialNumber"])
        _add_finding(
            findings,
            severity="high",
            rule_id="CLD-002",
            resource_type="identity",
            resource_id=target_user,
            title="MFA device was disabled or deleted",
            evidence=f"{event_name} was called by {actor} from {source_ip} at {event_time}.",
            impact="Disabling MFA weakens account protection and may be part of account takeover or persistence activity.",
            remediation="Confirm the MFA change was authorized and re-enable MFA for affected users.",
            references=[REF_AWS_CLOUDTRAIL, REF_AWS_IAM_BEST_PRACTICES, REF_MITRE_ACCOUNT_MANIPULATION],
            metadata=base_metadata,
        )

    if _event_matches(event, SECURITY_GROUP_CHANGE_EVENTS):
        group_id = _resource_from_params(event, ["groupId", "groupName"])
        _add_finding(
            findings,
            severity="medium",
            rule_id="CLD-003",
            resource_type="security_group",
            resource_id=group_id,
            title="Security group configuration changed",
            evidence=f"{event_name} was called by {actor} from {source_ip} at {event_time}.",
            impact="Security group changes can expose services, enable lateral movement, or weaken network controls.",
            remediation="Review the rule change, verify the business need, and revert unauthorized exposure.",
            references=[REF_AWS_CLOUDTRAIL, REF_MITRE_INFRA_MODIFY],
            metadata=base_metadata,
        )

    if _event_matches(event, BUCKET_POLICY_CHANGE_EVENTS):
        bucket_name = _resource_from_params(event, ["bucketName", "bucket"])
        _add_finding(
            findings,
            severity="high",
            rule_id="CLD-004",
            resource_type="bucket",
            resource_id=bucket_name,
            title="Bucket access policy changed",
            evidence=f"{event_name} was called by {actor} from {source_ip} at {event_time}.",
            impact="Bucket policy or public-access changes can expose cloud storage data.",
            remediation="Review the bucket policy diff and restore least-privilege access if the change was not approved.",
            references=[REF_AWS_CLOUDTRAIL, REF_AWS_S3_BUCKET_POLICIES, REF_MITRE_DATA_MANIPULATION],
            metadata=base_metadata,
        )

    if _event_matches(event, IAM_POLICY_CHANGE_EVENTS):
        policy_id = _resource_from_params(event, ["policyArn", "policyName", "roleName", "userName"])
        _add_finding(
            findings,
            severity="high",
            rule_id="CLD-005",
            resource_type="iam_policy",
            resource_id=policy_id,
            title="IAM policy configuration changed",
            evidence=f"{event_name} was called by {actor} from {source_ip} at {event_time}.",
            impact="IAM policy changes can grant new permissions, create persistence, or weaken least privilege.",
            remediation="Review the IAM policy change and confirm it matches an approved access request.",
            references=[REF_AWS_CLOUDTRAIL, REF_AWS_IAM_BEST_PRACTICES, REF_MITRE_ACCOUNT_MANIPULATION],
            metadata=base_metadata,
        )

    if _console_login_without_mfa(event):
        _add_finding(
            findings,
            severity="high",
            rule_id="CLD-007",
            resource_type="identity",
            resource_id=actor,
            title="IAM user console login did not use MFA",
            evidence=f"{actor} completed ConsoleLogin without MFA from {source_ip} at {event_time}.",
            impact="A password-only console session has less resistance to stolen credentials and account takeover.",
            remediation="Validate the login, require MFA for the user, and investigate the source and subsequent activity.",
            references=[
                REF_AWS_CLOUDTRAIL_RECORD,
                REF_AWS_IAM_BEST_PRACTICES,
                REF_MITRE_CLOUD_ACCOUNTS,
            ],
            metadata=base_metadata,
        )

    if _event_matches(event, CREDENTIAL_CREATION_EVENTS):
        target_user = _resource_from_params(event, ["userName"])
        if target_user == "unknown-resource":
            target_user = actor
        _add_finding(
            findings,
            severity="high",
            rule_id="CLD-008",
            resource_type="identity",
            resource_id=target_user,
            title="Persistent cloud credential was created",
            evidence=f"{event_name} was called by {actor} from {source_ip} at {event_time}.",
            impact="A new key, password, certificate, or service credential can provide persistent access outside the original session.",
            remediation="Confirm the credential was approved, identify where it was stored, and remove or rotate it if unauthorized.",
            references=[
                REF_AWS_IAM_CREATE_ACCESS_KEY,
                REF_MITRE_ADDITIONAL_CREDENTIALS,
            ],
            metadata=base_metadata,
        )

    if _event_matches(event, ROLE_TRUST_CHANGE_EVENTS):
        role_name = _resource_from_params(event, ["roleName"])
        _add_finding(
            findings,
            severity="high",
            rule_id="CLD-009",
            resource_type="role",
            resource_id=role_name,
            title="Role trust policy was changed",
            evidence=f"UpdateAssumeRolePolicy was called by {actor} from {source_ip} at {event_time}.",
            impact="A changed trust policy can let a new principal assume the role and retain or escalate access.",
            remediation="Review the trust-policy diff, validate every principal and condition, and remove unapproved trust.",
            references=[
                REF_AWS_IAM_UPDATE_TRUST,
                REF_MITRE_ADDITIONAL_ROLES,
            ],
            metadata=base_metadata,
        )

    if _monitoring_was_disabled(event):
        control_id = _resource_from_params(
            event,
            [
                "name",
                "trailName",
                "detectorId",
                "configurationRecorderName",
                "deliveryChannelName",
                "flowLogId",
            ],
        )
        _add_finding(
            findings,
            severity=(
                "critical"
                if event_name
                in {
                    "DeleteDetector",
                    "DeleteTrail",
                    "DisableSecurityHub",
                    "StopLogging",
                    "UpdateDetector",
                }
                else "high"
            ),
            rule_id="CLD-010",
            resource_type="security_control",
            resource_id=control_id,
            title="Audit or threat-detection control was disabled",
            evidence=f"{event_name} was called by {actor} from {source_ip} at {event_time}.",
            impact="Disabling logging or detection reduces visibility and can conceal later malicious activity.",
            remediation="Confirm authorization, restore the control, verify telemetry continuity, and investigate surrounding activity.",
            references=_monitoring_references(event_name),
            metadata=base_metadata,
        )

    if _event_matches(event, KMS_DISRUPTION_EVENTS):
        key_id = _resource_from_params(event, ["keyId"])
        scheduled_deletion = event_name == "ScheduleKeyDeletion"
        _add_finding(
            findings,
            severity="critical" if scheduled_deletion else "high",
            rule_id="CLD-011",
            resource_type="kms_key",
            resource_id=key_id,
            title=(
                "KMS key was scheduled for deletion"
                if scheduled_deletion
                else "KMS key was disabled"
            ),
            evidence=f"{event_name} was called by {actor} from {source_ip} at {event_time}.",
            impact=(
                "Deleting the key can permanently make dependent encrypted data unrecoverable."
                if scheduled_deletion
                else "Disabling the key can interrupt workloads and access to dependent encrypted data."
            ),
            remediation="Validate the change, cancel unauthorized deletion or re-enable the key, and identify dependent resources.",
            references=[
                REF_AWS_KMS_DELETE,
                REF_MITRE_DATA_DESTRUCTION,
            ],
            metadata=base_metadata,
        )

    return findings


def _first_qualifying_failure_window(
    ordered: list[_TimedFailureEvent],
    *,
    threshold: int = 5,
    window: timedelta,
) -> list[_TimedFailureEvent] | None:
    """Return the first qualifying maximal window using a monotonic right edge."""

    right = 0
    for left, (start_time, _, _) in enumerate(ordered):
        if right < left:
            right = left
        while (
            right < len(ordered)
            and ordered[right][0] - start_time <= window
        ):
            right += 1
        if right - left >= threshold:
            return ordered[left:right]
    return None


def detect_api_failure_spikes(
    events: list[dict[str, Any]],
    *,
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[Finding]:
    groups: dict[
        tuple[str, str, str],
        list[_TimedFailureEvent],
    ] = defaultdict(list)
    for index, event in enumerate(events):
        if event.get("errorCode"):
            groups[
                (
                    _event_account_id(event),
                    _actor(event),
                    _source_ip(event),
                )
            ].append((_event_time(event), index, event))

    findings: list[Finding] = []
    window = timedelta(minutes=window_minutes)
    for (account_id, actor, source_ip), group_events in groups.items():
        ordered = sorted(group_events, key=lambda item: item[0])
        window_events = _first_qualifying_failure_window(
            ordered,
            threshold=threshold,
            window=window,
        )
        if window_events is None:
            continue

        start_event = window_events[0][2]
        last_event = window_events[-1][2]
        event_names = sorted(
            {_event_name(event) for _, _, event in window_events}
        )
        error_codes = sorted(
            {str(event.get("errorCode")) for _, _, event in window_events}
        )
        event_ids = [
            _event_id(event, original_index)
            for _, original_index, event in window_events
        ]
        _add_finding(
            findings,
            severity="medium",
            rule_id="CLD-006",
            resource_type="api_activity",
            resource_id=f"{actor}@{source_ip}",
            title="Repeated API failures from one actor and source",
            evidence=(
                f"{len(window_events)} failed API call(s) from {actor} at {source_ip} "
                f"within {window_minutes} minutes starting {start_event.get('eventTime')}."
            ),
            impact="Repeated failed API calls may indicate credential misuse, probing, or brute-force style activity.",
            remediation="Review the source IP, actor, failed API names, and related authentication activity.",
            references=[REF_AWS_CLOUDTRAIL, REF_MITRE_BRUTE_FORCE],
            metadata={
                "actor": actor,
                "source_ip": source_ip,
                "event_names": ", ".join(event_names),
                "error_codes": ", ".join(error_codes),
                "event_ids": ", ".join(event_ids),
                "first_seen": str(start_event.get("eventTime", "unknown-time")),
                "last_seen": str(last_event.get("eventTime", "unknown-time")),
                "event_time": str(start_event.get("eventTime", "unknown-time")),
                "window_minutes": str(window_minutes),
                "failure_count": str(len(window_events)),
                "account_id": account_id,
                "aws_region": (
                    next(iter(regions))
                    if len(
                        regions := {
                            str(event.get("awsRegion"))
                            for _, _, event in window_events
                            if event.get("awsRegion")
                        }
                    )
                    == 1
                    else "multiple"
                ),
            },
        )

    return findings


def _deduplicate_events(environment: dict[str, Any]) -> list[dict[str, Any]]:
    raw_events = [event for event in environment.get("events", []) if isinstance(event, dict)]
    events: list[dict[str, Any]] = []
    seen_event_ids: set[str] = set()
    for event in raw_events:
        event_id = event.get("eventID")
        if event_id:
            normalized_event_id = str(event_id)
            if normalized_event_id in seen_event_ids:
                continue
            seen_event_ids.add(normalized_event_id)
        events.append(event)
    return events


def analyze_activity(
    environment: dict[str, Any],
    *,
    failure_threshold: int = 5,
    failure_window_minutes: int = 10,
    correlation_window_minutes: int = DEFAULT_CORRELATION_WINDOW_MINUTES,
) -> CloudTrailAnalysisResult:
    for name, value in (
        ("failure_threshold", failure_threshold),
        ("failure_window_minutes", failure_window_minutes),
        ("correlation_window_minutes", correlation_window_minutes),
    ):
        if value <= 0:
            raise ValueError(f"{name} must be greater than zero.")

    events = _deduplicate_events(environment)
    findings: list[Finding] = []

    for index, event in enumerate(events):
        findings.extend(analyze_single_event(event, index))

    findings.extend(
        detect_api_failure_spikes(
            events,
            threshold=failure_threshold,
            window_minutes=failure_window_minutes,
        )
    )
    sorted_findings = sort_findings(
        with_findings_context(
            findings,
            account_id=str(environment.get("account_id") or "unknown"),
        )
    )
    incidents = correlate_incidents(
        sorted_findings,
        window_minutes=correlation_window_minutes,
    )
    return CloudTrailAnalysisResult(
        findings=tuple(sorted_findings),
        incidents=tuple(incidents),
    )


def analyze_environment(
    environment: dict[str, Any],
    *,
    failure_threshold: int = 5,
    failure_window_minutes: int = 10,
) -> list[Finding]:
    return list(
        analyze_activity(
            environment,
            failure_threshold=failure_threshold,
            failure_window_minutes=failure_window_minutes,
        ).findings
    )


def load_environment(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("CloudTrail event file must contain a JSON object.")
    return data


def print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("No CloudTrail findings detected.")
        return

    print(f"CloudTrail findings detected: {len(findings)}")
    print()
    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.rule_id} {finding.resource_type}/{finding.resource_id}")
        print(f"Title: {finding.title}")
        print(f"Evidence: {finding.evidence}")
        print(f"Impact: {finding.impact}")
        print(f"Remediation: {finding.remediation}")
        print()


def print_incidents(incidents: list[Incident]) -> None:
    if not incidents:
        print("No correlated CloudTrail incidents detected.")
        return

    print(f"Correlated CloudTrail incidents detected: {len(incidents)}")
    print()
    for incident in incidents:
        print(f"[{incident.severity.upper()}] {incident.incident_id} {incident.title}")
        print(f"Actor: {incident.actor}")
        print(f"Source: {incident.source_ip}")
        print(f"Window: {incident.first_seen} to {incident.last_seen}")
        print(f"Rules: {', '.join(incident.rule_ids)}")
        print(f"Summary: {incident.summary}")
        print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze offline CloudTrail-style event JSON data for suspicious activity."
    )
    parser.add_argument("input", type=Path, help="Path to the sample CloudTrail-style event JSON file.")
    parser.add_argument("--output", type=Path, help="Optional path for JSON findings export.")
    parser.add_argument(
        "--incidents-output",
        type=Path,
        help="Optional path for correlated incident JSON export.",
    )
    parser.add_argument(
        "--failure-threshold",
        type=int,
        default=5,
        help="Failed API call threshold for spike detection.",
    )
    parser.add_argument(
        "--failure-window-minutes",
        type=int,
        default=10,
        help="Time window for failed API spike detection.",
    )
    parser.add_argument(
        "--correlation-window-minutes",
        type=int,
        default=DEFAULT_CORRELATION_WINDOW_MINUTES,
        help="Bounded time window used to correlate related findings.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        environment = load_environment(args.input)
        result = analyze_activity(
            environment,
            failure_threshold=args.failure_threshold,
            failure_window_minutes=args.failure_window_minutes,
            correlation_window_minutes=args.correlation_window_minutes,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    findings = list(result.findings)
    incidents = list(result.incidents)
    print_findings(findings)
    print_incidents(incidents)

    if args.output:
        write_findings(args.output, findings)
        print(f"Findings saved to {args.output}")
    if args.incidents_output:
        write_incidents(args.incidents_output, incidents)
        print(f"Incidents saved to {args.incidents_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
