import json
import tempfile
import unittest
from pathlib import Path

from cloud_findings import findings_to_dicts, write_findings
from cloudtrail_detector.detector import analyze_environment, load_environment

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FILE = PROJECT_ROOT / "sample_data" / "cloudtrail" / "sample_cloudtrail_events.json"


class CloudTrailDetectorTests(unittest.TestCase):
    def test_sample_events_detect_expected_cloudtrail_risks(self):
        environment = load_environment(SAMPLE_FILE)

        findings = analyze_environment(environment)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertEqual(6, len(findings))
        self.assertIn("CLD-001", rule_ids)
        self.assertIn("CLD-002", rule_ids)
        self.assertIn("CLD-003", rule_ids)
        self.assertIn("CLD-004", rule_ids)
        self.assertIn("CLD-005", rule_ids)
        self.assertIn("CLD-006", rule_ids)
        self.assertTrue(all(finding.module == "cloudtrail" for finding in findings))
        self.assertTrue(all(finding.category == "audit-and-detection" for finding in findings))
        self.assertTrue(all(finding.references for finding in findings))
        cld_004 = next(finding for finding in findings if finding.rule_id == "CLD-004")
        self.assertGreaterEqual(len(cld_004.references), 2)

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
            ["RevokeSecurityGroupIngress", "DeleteBucketPolicy", "DetachUserPolicy"]
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


if __name__ == "__main__":
    unittest.main()
