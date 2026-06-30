"""Detect suspicious activity in offline CloudTrail-style event data."""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cloud_findings import Finding, findings_to_dicts, sort_findings, write_findings


REF_AWS_CLOUDTRAIL = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html"
REF_AWS_IAM_BEST_PRACTICES = "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
REF_MITRE_CLOUD_ACCOUNTS = "https://attack.mitre.org/techniques/T1078/004/"
REF_MITRE_ACCOUNT_MANIPULATION = "https://attack.mitre.org/techniques/T1098/"
REF_MITRE_INFRA_MODIFY = "https://attack.mitre.org/techniques/T1578/005/"
REF_MITRE_BRUTE_FORCE = "https://attack.mitre.org/techniques/T1110/"

MFA_DISABLE_EVENTS = {"DeactivateMFADevice", "DeleteVirtualMFADevice"}
SECURITY_GROUP_CHANGE_EVENTS = {
    "AuthorizeSecurityGroupIngress",
    "RevokeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupEgress",
    "CreateSecurityGroup",
    "DeleteSecurityGroup",
}
BUCKET_POLICY_CHANGE_EVENTS = {
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "PutBucketAcl",
    "PutPublicAccessBlock",
    "DeletePublicAccessBlock",
}
IAM_POLICY_CHANGE_EVENTS = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "CreatePolicy",
    "CreatePolicyVersion",
    "DeletePolicy",
    "DeletePolicyVersion",
    "DetachUserPolicy",
    "DetachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "SetDefaultPolicyVersion",
}


def _actor(event: dict[str, Any]) -> str:
    identity = event.get("userIdentity", {})
    return str(
        identity.get("userName")
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


def _source_ip(event: dict[str, Any]) -> str:
    return str(event.get("sourceIPAddress", "unknown-source"))


def _resource_from_params(event: dict[str, Any], keys: list[str]) -> str:
    params = event.get("requestParameters", {})
    if not isinstance(params, dict):
        return "unknown-resource"
    for key in keys:
        value = params.get(key)
        if value:
            return str(value)
    return "unknown-resource"


def _event_id(event: dict[str, Any], index: int) -> str:
    return str(event.get("eventID") or f"{_event_name(event)}-{index + 1}")


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
            metadata=metadata or {},
        )
    )


def analyze_single_event(event: dict[str, Any], index: int) -> list[Finding]:
    findings: list[Finding] = []
    event_name = _event_name(event)
    actor = _actor(event)
    source_ip = _source_ip(event)
    event_time = str(event.get("eventTime", "unknown-time"))
    identity_type = str(event.get("userIdentity", {}).get("type", "unknown"))
    base_metadata = {
        "event_name": event_name,
        "event_time": event_time,
        "source_ip": source_ip,
        "actor": actor,
    }

    if event_name == "ConsoleLogin" and identity_type.lower() == "root":
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

    if event_name in MFA_DISABLE_EVENTS:
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

    if event_name in SECURITY_GROUP_CHANGE_EVENTS:
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

    if event_name in BUCKET_POLICY_CHANGE_EVENTS:
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
            references=[REF_AWS_CLOUDTRAIL],
            metadata=base_metadata,
        )

    if event_name in IAM_POLICY_CHANGE_EVENTS:
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

    return findings


def detect_api_failure_spikes(
    events: list[dict[str, Any]],
    *,
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[Finding]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("errorCode"):
            groups[(_actor(event), _source_ip(event))].append(event)

    findings: list[Finding] = []
    window = timedelta(minutes=window_minutes)
    for (actor, source_ip), group_events in groups.items():
        ordered = sorted(group_events, key=_event_time)
        for start_index, start_event in enumerate(ordered):
            start_time = _event_time(start_event)
            window_events = [
                event for event in ordered[start_index:] if _event_time(event) - start_time <= window
            ]
            if len(window_events) >= threshold:
                event_names = sorted({_event_name(event) for event in window_events})
                error_codes = sorted({str(event.get("errorCode")) for event in window_events})
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
                        "window_minutes": str(window_minutes),
                        "failure_count": str(len(window_events)),
                    },
                )
                break

    return findings


def analyze_environment(
    environment: dict[str, Any],
    *,
    failure_threshold: int = 5,
    failure_window_minutes: int = 10,
) -> list[Finding]:
    events = [event for event in environment.get("events", []) if isinstance(event, dict)]
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
    return sort_findings(findings)


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze offline CloudTrail-style event JSON data for suspicious activity."
    )
    parser.add_argument("input", type=Path, help="Path to the sample CloudTrail-style event JSON file.")
    parser.add_argument("--output", type=Path, help="Optional path for JSON findings export.")
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
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        environment = load_environment(args.input)
        findings = analyze_environment(
            environment,
            failure_threshold=args.failure_threshold,
            failure_window_minutes=args.failure_window_minutes,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    print_findings(findings)

    if args.output:
        write_findings(args.output, findings)
        print(f"Findings saved to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
