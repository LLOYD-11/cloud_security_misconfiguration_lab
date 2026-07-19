import json
import random
import tempfile
import unittest
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cloud_findings import EvidenceReference, Finding, findings_to_dicts, write_findings
from cloud_incidents import incidents_to_dicts, write_incidents
from cloudtrail_detector import detector as detector_module
from cloudtrail_detector.correlation import correlate_incidents
from cloudtrail_detector.detector import (
    analyze_activity,
    analyze_environment,
    load_environment,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FILE = PROJECT_ROOT / "sample_data" / "cloudtrail" / "sample_cloudtrail_events.json"


def _quadratic_failure_spike_reference(
    events: list[dict[str, Any]],
    *,
    threshold: int,
    window_minutes: int,
) -> list[Finding]:
    """Frozen C1 implementation used only as a behavioral oracle."""

    groups = defaultdict(list)
    for index, event in enumerate(events):
        if event.get("errorCode"):
            groups[
                (
                    detector_module._event_account_id(event),
                    detector_module._actor(event),
                    detector_module._source_ip(event),
                )
            ].append((index, event))

    findings = []
    window = timedelta(minutes=window_minutes)
    for (account_id, actor, source_ip), group_events in groups.items():
        ordered = sorted(
            group_events,
            key=lambda item: detector_module._event_time(item[1]),
        )
        for start_index, (_, start_event) in enumerate(ordered):
            start_time = detector_module._event_time(start_event)
            window_events = [
                item
                for item in ordered[start_index:]
                if detector_module._event_time(item[1]) - start_time <= window
            ]
            if len(window_events) < threshold:
                continue

            event_names = sorted(
                {
                    detector_module._event_name(event)
                    for _, event in window_events
                }
            )
            error_codes = sorted(
                {str(event.get("errorCode")) for _, event in window_events}
            )
            event_ids = [
                detector_module._event_id(event, original_index)
                for original_index, event in window_events
            ]
            last_event = window_events[-1][1]
            detector_module._add_finding(
                findings,
                severity="medium",
                rule_id="CLD-006",
                resource_type="api_activity",
                resource_id=f"{actor}@{source_ip}",
                title="Repeated API failures from one actor and source",
                evidence=(
                    f"{len(window_events)} failed API call(s) from {actor} at "
                    f"{source_ip} within {window_minutes} minutes starting "
                    f"{start_event.get('eventTime')}."
                ),
                impact=(
                    "Repeated failed API calls may indicate credential misuse, "
                    "probing, or brute-force style activity."
                ),
                remediation=(
                    "Review the source IP, actor, failed API names, and related "
                    "authentication activity."
                ),
                references=[
                    detector_module.REF_AWS_CLOUDTRAIL,
                    detector_module.REF_MITRE_BRUTE_FORCE,
                ],
                metadata={
                    "actor": actor,
                    "source_ip": source_ip,
                    "event_names": ", ".join(event_names),
                    "error_codes": ", ".join(error_codes),
                    "event_ids": ", ".join(event_ids),
                    "first_seen": str(
                        start_event.get("eventTime", "unknown-time")
                    ),
                    "last_seen": str(
                        last_event.get("eventTime", "unknown-time")
                    ),
                    "event_time": str(
                        start_event.get("eventTime", "unknown-time")
                    ),
                    "window_minutes": str(window_minutes),
                    "failure_count": str(len(window_events)),
                    "account_id": account_id,
                    "aws_region": (
                        next(iter(regions))
                        if len(
                            regions := {
                                str(event.get("awsRegion"))
                                for _, event in window_events
                                if event.get("awsRegion")
                            }
                        )
                        == 1
                        else "multiple"
                    ),
                },
            )
            break
    return findings


def _scaled_failure_corpus() -> list[dict[str, Any]]:
    rng = random.Random(20260718)
    base = datetime(2026, 6, 30, tzinfo=timezone.utc)
    events = []
    event_names = (
        "AssumeRole",
        "ListBuckets",
        "GetObject",
        "DescribeInstances",
    )
    error_codes = (
        "AccessDenied",
        "UnauthorizedOperation",
        "ThrottlingException",
    )
    regions = ("ap-southeast-2", "us-east-1")
    accounts = ("111122223333", "999988887777")

    for group_index in range(80):
        actor = f"scale-user-{group_index:03d}"
        source_ip = f"192.0.2.{group_index % 200 + 1}"
        account_id = accounts[group_index % len(accounts)]
        group_base = base + timedelta(hours=group_index)
        for event_index in range(36):
            observed_at = group_base + timedelta(
                seconds=rng.randrange(0, 30 * 60)
            )
            event = {
                "eventID": f"scale-{group_index:03d}-{event_index:03d}",
                "eventTime": observed_at.isoformat().replace("+00:00", "Z"),
                "eventName": event_names[event_index % len(event_names)],
                "recipientAccountId": account_id,
                "awsRegion": regions[event_index % len(regions)],
                "sourceIPAddress": source_ip,
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": actor,
                },
            }
            if event_index % 7 != 0:
                event["errorCode"] = error_codes[
                    event_index % len(error_codes)
                ]
            events.append(event)
    rng.shuffle(events)
    return events


class _CountingTimestamp:
    subtractions = 0

    def __init__(self, value: datetime) -> None:
        self.value = value

    def __sub__(self, other: "_CountingTimestamp") -> timedelta:
        type(self).subtractions += 1
        return self.value - other.value


class CloudTrailDetectorTests(unittest.TestCase):
    def test_sample_events_detect_expected_cloudtrail_risks(self):
        environment = load_environment(SAMPLE_FILE)

        findings = analyze_environment(environment)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertEqual(11, len(findings))
        self.assertIn("CLD-001", rule_ids)
        self.assertIn("CLD-002", rule_ids)
        self.assertIn("CLD-003", rule_ids)
        self.assertIn("CLD-004", rule_ids)
        self.assertIn("CLD-005", rule_ids)
        self.assertIn("CLD-006", rule_ids)
        self.assertIn("CLD-007", rule_ids)
        self.assertIn("CLD-008", rule_ids)
        self.assertIn("CLD-009", rule_ids)
        self.assertIn("CLD-010", rule_ids)
        self.assertIn("CLD-011", rule_ids)
        self.assertTrue(all(finding.module == "cloudtrail" for finding in findings))
        self.assertTrue(all(finding.category == "audit-and-detection" for finding in findings))
        self.assertTrue(all(finding.references for finding in findings))
        cld_004 = next(finding for finding in findings if finding.rule_id == "CLD-004")
        self.assertGreaterEqual(len(cld_004.references), 2)

    def test_sample_events_correlate_attack_chain_and_failure_burst(self):
        environment = load_environment(SAMPLE_FILE)

        first_result = analyze_activity(environment)
        second_result = analyze_activity(environment)

        self.assertEqual(2, len(first_result.incidents))
        self.assertEqual(first_result.incidents, second_result.incidents)
        attack_chain = next(
            incident
            for incident in first_result.incidents
            if incident.actor == "alice-admin"
        )
        self.assertEqual("critical", attack_chain.severity)
        self.assertEqual("high", attack_chain.confidence)
        self.assertEqual(8, attack_chain.event_count)
        self.assertEqual(
            {
                "CLD-002",
                "CLD-003",
                "CLD-004",
                "CLD-005",
                "CLD-008",
                "CLD-009",
                "CLD-010",
                "CLD-011",
            },
            set(attack_chain.rule_ids),
        )
        failure_incident = next(
            incident
            for incident in first_result.incidents
            if incident.actor == "unknown-user"
        )
        self.assertEqual(["CLD-006"], failure_incident.rule_ids)
        self.assertEqual(6, failure_incident.event_count)
        self.assertEqual("medium", failure_incident.confidence)

    def test_benign_read_only_event_has_no_findings(self):
        environment = {
            "events": [
                {
                    "eventTime": "2026-06-30T03:00:00Z",
                    "eventSource": "ec2.amazonaws.com",
                    "eventName": "DescribeInstances",
                    "sourceIPAddress": "10.0.1.25",
                    "userIdentity": {
                        "type": "AssumedRole",
                        "userName": "readonly-audit-role",
                    },
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertEqual([], findings)

    def test_change_rules_require_the_expected_aws_service_source(self):
        cases = (
            (
                "CLD-001",
                "signin.amazonaws.com",
                {
                    "eventName": "ConsoleLogin",
                    "responseElements": {"ConsoleLogin": "Success"},
                    "userIdentity": {"type": "Root"},
                },
            ),
            (
                "CLD-002",
                "iam.amazonaws.com",
                {
                    "eventName": "DeactivateMFADevice",
                    "requestParameters": {"userName": "alice"},
                },
            ),
            (
                "CLD-003",
                "ec2.amazonaws.com",
                {
                    "eventName": "AuthorizeSecurityGroupIngress",
                    "requestParameters": {"groupId": "sg-123"},
                },
            ),
            (
                "CLD-004",
                "s3.amazonaws.com",
                {
                    "eventName": "PutBucketPolicy",
                    "requestParameters": {"bucketName": "example"},
                },
            ),
            (
                "CLD-005",
                "iam.amazonaws.com",
                {
                    "eventName": "CreatePolicyVersion",
                    "requestParameters": {"policyName": "Example"},
                },
            ),
            (
                "CLD-007",
                "signin.amazonaws.com",
                {
                    "eventName": "ConsoleLogin",
                    "responseElements": {"ConsoleLogin": "Success"},
                    "additionalEventData": {"MFAUsed": "No"},
                },
            ),
            (
                "CLD-008",
                "iam.amazonaws.com",
                {
                    "eventName": "CreateAccessKey",
                    "requestParameters": {"userName": "alice"},
                },
            ),
            (
                "CLD-009",
                "iam.amazonaws.com",
                {
                    "eventName": "UpdateAssumeRolePolicy",
                    "requestParameters": {"roleName": "Example"},
                },
            ),
            (
                "CLD-010",
                "guardduty.amazonaws.com",
                {
                    "eventName": "DeleteDetector",
                    "requestParameters": {"detectorId": "detector-1"},
                },
            ),
            (
                "CLD-011",
                "kms.amazonaws.com",
                {
                    "eventName": "ScheduleKeyDeletion",
                    "requestParameters": {"keyId": "key-1"},
                },
            ),
        )
        for rule_id, event_source, overrides in cases:
            with self.subTest(rule_id=rule_id):
                event = {
                    "eventID": f"event-{rule_id.lower()}",
                    "eventTime": "2026-06-30T01:00:00Z",
                    "eventSource": event_source,
                    "sourceIPAddress": "192.0.2.1",
                    "userIdentity": {
                        "type": "IAMUser",
                        "userName": "alice",
                    },
                    **overrides,
                }

                matching = analyze_environment({"events": [event]})
                wrong_source = analyze_environment(
                    {
                        "events": [
                            {
                                **event,
                                "eventSource": "unrelated.amazonaws.com",
                            }
                        ]
                    }
                )

                self.assertEqual([rule_id], [finding.rule_id for finding in matching])
                self.assertEqual([], wrong_source)

    def test_event_source_map_covers_every_supported_change_event(self):
        expected_by_source = {
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
                "AuthorizeSecurityGroupEgress",
                "AuthorizeSecurityGroupIngress",
                "DeleteFlowLogs",
            },
            "guardduty.amazonaws.com": {
                "DeleteDetector",
                "UpdateDetector",
            },
            "iam.amazonaws.com": {
                "AttachRolePolicy",
                "AttachUserPolicy",
                "CreateAccessKey",
                "CreateLoginProfile",
                "CreatePolicy",
                "CreatePolicyVersion",
                "CreateServiceSpecificCredential",
                "DeactivateMFADevice",
                "DeleteVirtualMFADevice",
                "PutRolePolicy",
                "PutUserPolicy",
                "SetDefaultPolicyVersion",
                "UpdateAssumeRolePolicy",
                "UploadSSHPublicKey",
                "UploadSigningCertificate",
            },
            "kms.amazonaws.com": {
                "DisableKey",
                "ScheduleKeyDeletion",
            },
            "s3.amazonaws.com": {
                "DeletePublicAccessBlock",
                "PutBucketAcl",
                "PutBucketPolicy",
            },
            "securityhub.amazonaws.com": {"DisableSecurityHub"},
            "signin.amazonaws.com": {"ConsoleLogin"},
        }

        self.assertEqual(expected_by_source, detector_module.EVENT_SOURCES)

    def test_failed_api_spike_requires_threshold_within_window(self):
        events = []
        for index in range(4):
            events.append(
                {
                    "eventTime": f"2026-06-30T02:0{index}:00Z",
                    "eventName": "AssumeRole",
                    "sourceIPAddress": "192.0.2.44",
                    "userIdentity": {
                        "type": "IAMUser",
                        "userName": "unknown-user",
                    },
                    "errorCode": "AccessDenied",
                }
            )
        environment = {"events": events}

        findings = analyze_environment(environment)

        self.assertEqual([], findings)

    def test_failed_api_spike_groups_by_actor_and_source_ip(self):
        events = []
        for index in range(5):
            events.append(
                {
                    "eventTime": f"2026-06-30T02:0{index}:00Z",
                    "eventName": "AssumeRole",
                    "sourceIPAddress": "192.0.2.44",
                    "userIdentity": {
                        "type": "IAMUser",
                        "userName": "unknown-user",
                    },
                    "errorCode": "AccessDenied",
                }
            )
        for index in range(5):
            events.append(
                {
                    "eventTime": f"2026-06-30T02:0{index}:00Z",
                    "eventName": "AssumeRole",
                    "sourceIPAddress": "198.51.100.22",
                    "userIdentity": {
                        "type": "IAMUser",
                        "userName": "unknown-user",
                    },
                    "errorCode": "AccessDenied",
                }
            )
        environment = {"events": events}

        findings = analyze_environment(environment)

        self.assertEqual(["CLD-006", "CLD-006"], [finding.rule_id for finding in findings])
        self.assertEqual(
            {"unknown-user@192.0.2.44", "unknown-user@198.51.100.22"},
            {finding.resource_id for finding in findings},
        )

    def test_failure_window_preserves_first_anchor_and_inclusive_boundary(self):
        base_event = {
            "eventName": "AssumeRole",
            "sourceIPAddress": "192.0.2.44",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "boundary-user",
            },
            "errorCode": "AccessDenied",
        }
        for times, window_minutes, expected_ids in (
            (
                ("02:00:00", "02:05:00", "02:10:00", "02:10:01"),
                10,
                ("boundary-0", "boundary-1", "boundary-2"),
            ),
            (
                ("02:00:00", "02:11:00", "02:12:00", "02:13:00"),
                2,
                ("boundary-1", "boundary-2", "boundary-3"),
            ),
        ):
            with self.subTest(times=times, window_minutes=window_minutes):
                events = [
                    {
                        **base_event,
                        "eventID": f"boundary-{index}",
                        "eventTime": f"2026-06-30T{event_time}Z",
                    }
                    for index, event_time in enumerate(times)
                ]

                finding = detector_module.detect_api_failure_spikes(
                    events,
                    threshold=3,
                    window_minutes=window_minutes,
                )[0]

                self.assertEqual(
                    ", ".join(expected_ids),
                    finding.metadata["event_ids"],
                )
                self.assertEqual(
                    sorted(expected_ids),
                    [
                        reference.id
                        for reference in finding.evidence_references
                    ],
                )
                first_index = int(expected_ids[0].rsplit("-", 1)[1])
                self.assertEqual(
                    f"2026-06-30T{times[first_index]}Z",
                    finding.observed_at,
                )

    def test_failure_spike_optimization_matches_quadratic_reference_at_scale(self):
        events = _scaled_failure_corpus()
        self.assertEqual(2_880, len(events))
        self.assertEqual(
            2_400,
            sum(bool(event.get("errorCode")) for event in events),
        )

        for threshold, window_minutes in (
            (1, 10),
            (3, 5),
            (5, 10),
            (12, 15),
            (50, 10),
        ):
            with self.subTest(
                threshold=threshold,
                window_minutes=window_minutes,
            ):
                expected = _quadratic_failure_spike_reference(
                    events,
                    threshold=threshold,
                    window_minutes=window_minutes,
                )
                actual = detector_module.detect_api_failure_spikes(
                    events,
                    threshold=threshold,
                    window_minutes=window_minutes,
                )

                self.assertEqual(expected, actual)

    def test_failure_window_two_pointer_uses_linear_timestamp_subtractions(self):
        base = datetime(2026, 6, 30, tzinfo=timezone.utc)
        event_count = 10_000
        _CountingTimestamp.subtractions = 0
        ordered = [
            (
                _CountingTimestamp(base + timedelta(seconds=index)),
                index,
                {},
            )
            for index in range(event_count)
        ]

        result = detector_module._first_qualifying_failure_window(
            ordered,
            threshold=event_count + 1,
            window=timedelta(seconds=30),
        )

        self.assertIsNone(result)
        self.assertLessEqual(
            _CountingTimestamp.subtractions,
            2 * event_count,
        )

    def test_failed_api_spikes_and_incidents_do_not_cross_account_boundaries(self):
        events = []
        for account_id in ("111122223333", "999988887777"):
            for index in range(5):
                events.append(
                    {
                        "eventID": f"{account_id}-failure-{index}",
                        "eventTime": f"2026-06-30T02:0{index}:00Z",
                        "eventName": "AssumeRole",
                        "recipientAccountId": account_id,
                        "sourceIPAddress": "192.0.2.44",
                        "userIdentity": {
                            "type": "IAMUser",
                            "userName": "unknown-user",
                        },
                        "errorCode": "AccessDenied",
                    }
                )

        result = analyze_activity({"events": events})

        self.assertEqual(2, len(result.findings))
        self.assertEqual(
            {"111122223333", "999988887777"},
            {finding.account_id for finding in result.findings},
        )
        self.assertEqual(2, len(result.incidents))
        self.assertTrue(
            all(incident.event_count == 5 for incident in result.incidents)
        )

    def test_failed_change_event_does_not_claim_resource_was_changed(self):
        environment = {
            "events": [
                {
                    "eventTime": "2026-06-30T01:00:00Z",
                    "eventName": "PutBucketPolicy",
                    "sourceIPAddress": "192.0.2.1",
                    "userIdentity": {"type": "IAMUser", "userName": "alice"},
                    "requestParameters": {"bucketName": "example"},
                    "errorCode": "AccessDenied",
                }
            ]
        }

        self.assertEqual([], analyze_environment(environment))

    def test_failed_root_console_login_is_not_reported_as_successful_login(self):
        environment = {
            "events": [
                {
                    "eventTime": "2026-06-30T01:00:00Z",
                    "eventName": "ConsoleLogin",
                    "sourceIPAddress": "192.0.2.1",
                    "userIdentity": {"type": "Root"},
                    "responseElements": {"ConsoleLogin": "Failure"},
                }
            ]
        }

        self.assertEqual([], analyze_environment(environment))

    def test_root_console_login_with_unknown_outcome_is_not_reported_as_successful(self):
        environment = {
            "events": [
                {
                    "eventTime": "2026-06-30T01:00:00Z",
                    "eventName": "ConsoleLogin",
                    "sourceIPAddress": "192.0.2.1",
                    "userIdentity": {"type": "Root"},
                    "responseElements": None,
                }
            ]
        }

        self.assertEqual([], analyze_environment(environment))

    def test_risk_reducing_change_events_are_not_reported_as_risky_changes(self):
        events = []
        for index, event_name in enumerate(
            [
                "RevokeSecurityGroupIngress",
                "DeleteBucketPolicy",
                "DetachUserPolicy",
                "StartLogging",
                "EnableKey",
                "CancelKeyDeletion",
            ]
        ):
            events.append(
                {
                    "eventTime": f"2026-06-30T01:0{index}:00Z",
                    "eventName": event_name,
                    "sourceIPAddress": "192.0.2.1",
                    "userIdentity": {"type": "IAMUser", "userName": "security-admin"},
                    "requestParameters": {},
                }
            )

        self.assertEqual([], analyze_environment({"events": events}))

    def test_duplicate_event_ids_are_analyzed_once(self):
        event = {
            "eventID": "duplicate-event",
            "eventTime": "2026-06-30T01:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "sourceIPAddress": "192.0.2.1",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
            "requestParameters": {"bucketName": "example"},
        }

        findings = analyze_environment({"events": [event, dict(event)]})

        self.assertEqual(["CLD-004"], [finding.rule_id for finding in findings])

    def test_conflicting_event_ids_are_rejected_in_any_input_order(self):
        dangerous = {
            "eventID": "duplicate-event",
            "eventTime": "2026-06-30T01:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "sourceIPAddress": "192.0.2.1",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
            "requestParameters": {"bucketName": "example"},
        }
        benign = {
            **dangerous,
            "eventName": "GetBucketPolicy",
        }

        for label, events in (
            ("dangerous-first", [dangerous, benign]),
            ("benign-first", [benign, dangerous]),
            (
                "conflict-after-identical",
                [dangerous, dict(dangerous), benign],
            ),
        ):
            with self.subTest(order=label), self.assertRaisesRegex(
                ValueError,
                "Conflicting CloudTrail events share eventID 'duplicate-event'",
            ):
                analyze_environment({"events": events})

    def test_conflicting_event_id_is_escaped_in_user_facing_error(self):
        event = {
            "eventID": "event-\n-injected",
            "eventTime": "2026-06-30T01:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "sourceIPAddress": "192.0.2.1",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
        }
        conflicting = {
            **event,
            "eventName": "GetBucketPolicy",
        }

        with self.assertRaises(ValueError) as context:
            analyze_environment({"events": [event, conflicting]})

        message = str(context.exception)
        self.assertNotIn("\n", message)
        self.assertIn(r"event-\n-injected", message)

    def test_iam_console_login_without_explicit_mfa_no_is_not_reported(self):
        base_event = {
            "eventTime": "2026-06-30T01:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "192.0.2.1",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
            "responseElements": {"ConsoleLogin": "Success"},
        }

        for additional_data in (None, {}, {"MFAUsed": "Yes"}):
            with self.subTest(additional_data=additional_data):
                event = dict(base_event)
                if additional_data is not None:
                    event["additionalEventData"] = additional_data
                self.assertEqual([], analyze_environment({"events": [event]}))

    def test_new_rule_catalog_detects_only_successful_supported_events(self):
        cases = (
            (
                "CreateAccessKey",
                "iam.amazonaws.com",
                {"userName": "backup-user"},
                "CLD-008",
                "backup-user",
            ),
            (
                "UpdateAssumeRolePolicy",
                "iam.amazonaws.com",
                {"roleName": "admin-role"},
                "CLD-009",
                "admin-role",
            ),
            (
                "DeleteDetector",
                "guardduty.amazonaws.com",
                {"detectorId": "detector-1"},
                "CLD-010",
                "detector-1",
            ),
            (
                "ScheduleKeyDeletion",
                "kms.amazonaws.com",
                {"keyId": "key-1"},
                "CLD-011",
                "key-1",
            ),
        )
        for event_name, event_source, request_parameters, rule_id, resource_id in cases:
            with self.subTest(event_name=event_name):
                event = {
                    "eventID": f"event-{event_name}",
                    "eventTime": "2026-06-30T01:00:00Z",
                    "eventSource": event_source,
                    "eventName": event_name,
                    "sourceIPAddress": "192.0.2.1",
                    "userIdentity": {"type": "IAMUser", "userName": "alice"},
                    "requestParameters": request_parameters,
                }
                findings = analyze_environment({"events": [event]})
                self.assertEqual([rule_id], [finding.rule_id for finding in findings])
                self.assertEqual(resource_id, findings[0].resource_id)

                failed_event = dict(event, errorCode="AccessDenied")
                self.assertEqual(
                    [],
                    analyze_environment(
                        {"events": [failed_event]},
                        failure_threshold=2,
                    ),
                )

    def test_update_detector_only_fires_when_explicitly_disabled(self):
        base_event = {
            "eventTime": "2026-06-30T01:00:00Z",
            "eventSource": "guardduty.amazonaws.com",
            "eventName": "UpdateDetector",
            "sourceIPAddress": "192.0.2.1",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
        }
        for enable, expected_rules in (
            (False, ["CLD-010"]),
            (True, []),
            (None, []),
        ):
            with self.subTest(enable=enable):
                event = dict(base_event)
                event["requestParameters"] = (
                    {} if enable is None else {"enable": enable, "detectorId": "detector-1"}
                )
                findings = analyze_environment({"events": [event]})
                self.assertEqual(expected_rules, [finding.rule_id for finding in findings])

    def test_lower_scope_monitoring_change_is_high_not_critical(self):
        event = {
            "eventTime": "2026-06-30T01:00:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DeleteFlowLogs",
            "sourceIPAddress": "192.0.2.1",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
            "requestParameters": {"flowLogId": "fl-1"},
        }

        finding = analyze_environment({"events": [event]})[0]

        self.assertEqual("CLD-010", finding.rule_id)
        self.assertEqual("high", finding.severity)

    def test_assumed_role_uses_session_issuer_for_stable_actor(self):
        environment = {
            "events": [
                {
                    "eventTime": "2026-06-30T01:00:00Z",
                    "eventSource": "s3.amazonaws.com",
                    "eventName": "PutBucketPolicy",
                    "sourceIPAddress": "192.0.2.1",
                    "userIdentity": {
                        "type": "AssumedRole",
                        "arn": "arn:aws:sts::111122223333:assumed-role/security-admin/session-a",
                        "sessionContext": {
                            "sessionIssuer": {
                                "arn": "arn:aws:iam::111122223333:role/security-admin",
                                "userName": "security-admin",
                            }
                        },
                    },
                    "requestParameters": {"bucketName": "example"},
                }
            ]
        }

        finding = analyze_environment(environment)[0]

        self.assertEqual("security-admin", finding.metadata["actor"])

    def test_correlation_requires_distinct_rules_events_actor_and_source(self):
        events = [
            {
                "eventID": "event-1",
                "eventTime": "2026-06-30T01:00:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketPolicy",
                "sourceIPAddress": "192.0.2.1",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
                "requestParameters": {"bucketName": "one"},
            },
            {
                "eventID": "event-2",
                "eventTime": "2026-06-30T01:01:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketPolicy",
                "sourceIPAddress": "192.0.2.1",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
                "requestParameters": {"bucketName": "two"},
            },
            {
                "eventID": "event-3",
                "eventTime": "2026-06-30T01:02:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateAccessKey",
                "sourceIPAddress": "198.51.100.1",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
                "requestParameters": {"userName": "alice"},
            },
            {
                "eventID": "event-4",
                "eventTime": "2026-06-30T01:03:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "UpdateAssumeRolePolicy",
                "sourceIPAddress": "198.51.100.1",
                "userIdentity": {"type": "IAMUser", "userName": "bob"},
                "requestParameters": {"roleName": "example"},
            },
        ]

        result = analyze_activity({"events": events})

        self.assertEqual(4, len(result.findings))
        self.assertEqual((), result.incidents)

    def test_correlation_does_not_join_missing_actor_or_source_context(self):
        events = [
            {
                "eventID": "event-1",
                "eventTime": "2026-06-30T01:00:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketPolicy",
                "userIdentity": [],
                "requestParameters": {"bucketName": "one"},
            },
            {
                "eventID": "event-2",
                "eventTime": "2026-06-30T01:01:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateAccessKey",
                "userIdentity": [],
                "requestParameters": {"userName": "alice"},
            },
        ]

        result = analyze_activity({"events": events})

        self.assertEqual(2, len(result.findings))
        self.assertEqual((), result.incidents)

    def test_correlation_window_is_bounded_from_cluster_anchor(self):
        events = [
            {
                "eventID": "event-1",
                "eventTime": "2026-06-30T01:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "DeactivateMFADevice",
                "sourceIPAddress": "192.0.2.1",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
                "requestParameters": {"userName": "alice"},
            },
            {
                "eventID": "event-2",
                "eventTime": "2026-06-30T01:11:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateAccessKey",
                "sourceIPAddress": "192.0.2.1",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
                "requestParameters": {"userName": "alice"},
            },
        ]

        outside = analyze_activity(
            {"events": events},
            correlation_window_minutes=10,
        )
        inside = analyze_activity(
            {"events": events},
            correlation_window_minutes=11,
        )

        self.assertEqual((), outside.incidents)
        self.assertEqual(1, len(inside.incidents))

    def test_correlation_uses_v2_time_and_evidence_references(self):
        findings = [
            Finding(
                rule_id=rule_id,
                severity="high",
                module="cloudtrail",
                category="audit-and-detection",
                resource_type="identity",
                resource_id="alice",
                title="Synthetic signal",
                evidence="Synthetic evidence.",
                impact="Synthetic impact.",
                remediation="Synthetic remediation.",
                references=["https://example.com/reference"],
                metadata={
                    "actor": "alice",
                    "source_ip": "192.0.2.1",
                    "event_time": legacy_event_time,
                },
                observed_at=observed_at,
                evidence_references=[
                    EvidenceReference(
                        type="cloudtrail-event",
                        id=event_id,
                    )
                ],
            )
            for rule_id, event_id, observed_at, legacy_event_time in (
                (
                    "CLD-002",
                    "event-v2-1",
                    "2026-06-30T01:00:00Z",
                    "2026-06-30T05:00:00Z",
                ),
                (
                    "CLD-008",
                    "event-v2-2",
                    "2026-06-30T01:01:00Z",
                    "2026-06-30T07:00:00Z",
                ),
            )
        ]

        incidents = correlate_incidents(findings)

        self.assertEqual(1, len(incidents))
        self.assertEqual(
            ["event-v2-1", "event-v2-2"],
            incidents[0].event_ids,
        )

    def test_findings_export_writes_shared_schema(self):
        environment = load_environment(SAMPLE_FILE)
        findings = analyze_environment(environment)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "cloudtrail_findings.json"
            write_findings(output_path, findings)
            payload = json.loads(output_path.read_text(encoding="utf-8"))

            self.assertEqual("2.0", payload["schema_version"])
        self.assertEqual(len(findings), payload["finding_count"])
        self.assertEqual(findings_to_dicts(findings), payload["findings"])

    def test_incident_export_writes_shared_schema(self):
        result = analyze_activity(load_environment(SAMPLE_FILE))

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "cloudtrail_incidents.json"
            write_incidents(output_path, result.incidents)
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual("1.0", payload["schema_version"])
        self.assertEqual(len(result.incidents), payload["incident_count"])
        self.assertEqual(incidents_to_dicts(result.incidents), payload["incidents"])


if __name__ == "__main__":
    unittest.main()
