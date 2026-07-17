import json
import tempfile
import unittest
from pathlib import Path

from cloud_findings import findings_to_dicts, write_findings
from cloud_incidents import incidents_to_dicts, write_incidents
from cloudtrail_detector.detector import (
    analyze_activity,
    analyze_environment,
    load_environment,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FILE = PROJECT_ROOT / "sample_data" / "cloudtrail" / "sample_cloudtrail_events.json"


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
            "eventName": "PutBucketPolicy",
            "sourceIPAddress": "192.0.2.1",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
            "requestParameters": {"bucketName": "example"},
        }

        findings = analyze_environment({"events": [event, dict(event)]})

        self.assertEqual(["CLD-004"], [finding.rule_id for finding in findings])

    def test_iam_console_login_without_explicit_mfa_no_is_not_reported(self):
        base_event = {
            "eventTime": "2026-06-30T01:00:00Z",
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
                {"userName": "backup-user"},
                "CLD-008",
                "backup-user",
            ),
            (
                "UpdateAssumeRolePolicy",
                {"roleName": "admin-role"},
                "CLD-009",
                "admin-role",
            ),
            (
                "DeleteDetector",
                {"detectorId": "detector-1"},
                "CLD-010",
                "detector-1",
            ),
            (
                "ScheduleKeyDeletion",
                {"keyId": "key-1"},
                "CLD-011",
                "key-1",
            ),
        )
        for event_name, request_parameters, rule_id, resource_id in cases:
            with self.subTest(event_name=event_name):
                event = {
                    "eventID": f"event-{event_name}",
                    "eventTime": "2026-06-30T01:00:00Z",
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
                "eventName": "PutBucketPolicy",
                "sourceIPAddress": "192.0.2.1",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
                "requestParameters": {"bucketName": "one"},
            },
            {
                "eventID": "event-2",
                "eventTime": "2026-06-30T01:01:00Z",
                "eventName": "PutBucketPolicy",
                "sourceIPAddress": "192.0.2.1",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
                "requestParameters": {"bucketName": "two"},
            },
            {
                "eventID": "event-3",
                "eventTime": "2026-06-30T01:02:00Z",
                "eventName": "CreateAccessKey",
                "sourceIPAddress": "198.51.100.1",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
                "requestParameters": {"userName": "alice"},
            },
            {
                "eventID": "event-4",
                "eventTime": "2026-06-30T01:03:00Z",
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
                "eventName": "PutBucketPolicy",
                "userIdentity": [],
                "requestParameters": {"bucketName": "one"},
            },
            {
                "eventID": "event-2",
                "eventTime": "2026-06-30T01:01:00Z",
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
                "eventName": "DeactivateMFADevice",
                "sourceIPAddress": "192.0.2.1",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
                "requestParameters": {"userName": "alice"},
            },
            {
                "eventID": "event-2",
                "eventTime": "2026-06-30T01:11:00Z",
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

    def test_findings_export_writes_shared_schema(self):
        environment = load_environment(SAMPLE_FILE)
        findings = analyze_environment(environment)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "cloudtrail_findings.json"
            write_findings(output_path, findings)
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual("1.0", payload["schema_version"])
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
