import copy
import gzip
import json
import tempfile
import unittest
from pathlib import Path

from cloud_security_lab.normalizers.cloudtrail import (
    load_aws_cloudtrail_environment,
    normalize_aws_cloudtrail_environment,
)
from cloudtrail_detector.detector import analyze_environment

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PATHS = (
    PROJECT_ROOT
    / "sample_data/aws/cloudtrail/111122223333_CloudTrail_20260630T0200Z_part1.json",
    PROJECT_ROOT
    / "sample_data/aws/cloudtrail/111122223333_CloudTrail_20260630T0300Z_part2.json.gz",
)


def _event(event_id: str = "00000000-0000-4000-8000-000000000001"):
    return {
        "eventVersion": "1.11",
        "userIdentity": {
            "type": "IAMUser",
            "accountId": "111122223333",
            "arn": "arn:aws:iam::111122223333:user/alice",
            "userName": "alice",
        },
        "eventTime": "2026-06-30T01:00:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "awsRegion": "ap-southeast-2",
        "sourceIPAddress": "192.0.2.1",
        "requestParameters": None,
        "responseElements": None,
        "eventID": event_id,
        "eventType": "AwsApiCall",
        "recipientAccountId": "111122223333",
        "eventCategory": "Management",
    }


class NativeCloudTrailNormalizerTests(unittest.TestCase):
    def test_native_json_and_gzip_samples_produce_expected_findings(self):
        result = load_aws_cloudtrail_environment(SAMPLE_PATHS)
        findings = analyze_environment(result.environment)

        self.assertEqual("111122223333", result.environment["account_id"])
        self.assertEqual(17, len(result.environment["events"]))
        self.assertEqual(11, len(findings))
        self.assertEqual(
            {
                "CLD-001",
                "CLD-002",
                "CLD-003",
                "CLD-004",
                "CLD-005",
                "CLD-006",
                "CLD-007",
                "CLD-008",
                "CLD-009",
                "CLD-010",
                "CLD-011",
            },
            {finding.rule_id for finding in findings},
        )
        self.assertEqual(1, len(result.warnings))
        self.assertIn("Skipped 1 duplicate", result.warnings[0])
        self.assertEqual("CLD_DUPLICATE_EVENT", result.skipped_evidence[0].code)
        self.assertFalse(result.skipped_evidence[0].affects_coverage)

    def test_duplicate_input_paths_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "provided more than once"):
            load_aws_cloudtrail_environment((SAMPLE_PATHS[0], SAMPLE_PATHS[0]))

    def test_identical_event_ids_are_deduplicated(self):
        event = _event()

        result = normalize_aws_cloudtrail_environment(
            ({"Records": [event]}, {"Records": [copy.deepcopy(event)]})
        )

        self.assertEqual(1, len(result.environment["events"]))
        self.assertIn("Skipped 1 duplicate", result.warnings[0])
        self.assertEqual(1, result.skipped_evidence[0].count)

    def test_conflicting_duplicate_event_ids_are_rejected(self):
        first = _event()
        second = copy.deepcopy(first)
        second["eventName"] = "StopInstances"

        with self.assertRaisesRegex(ValueError, "conflicts with another record"):
            normalize_aws_cloudtrail_environment(
                ({"Records": [first]}, {"Records": [second]})
            )

    def test_multiple_recipient_accounts_are_rejected(self):
        first = _event()
        second = _event("00000000-0000-4000-8000-000000000002")
        second["recipientAccountId"] = "999988887777"

        with self.assertRaisesRegex(ValueError, "multiple recipient account IDs"):
            normalize_aws_cloudtrail_environment(
                ({"Records": [first, second]},)
            )

    def test_missing_recipient_account_uses_identity_context_with_warning(self):
        event = _event()
        event.pop("recipientAccountId")

        result = normalize_aws_cloudtrail_environment(({"Records": [event]},))

        self.assertEqual("111122223333", result.environment["account_id"])
        self.assertIn("Derived account context", result.warnings[0])

        event["userIdentity"].pop("accountId")
        result = normalize_aws_cloudtrail_environment(({"Records": [event]},))
        self.assertEqual("111122223333", result.environment["account_id"])

    def test_missing_all_account_context_is_rejected(self):
        event = _event()
        event.pop("recipientAccountId")
        event["userIdentity"].pop("accountId")
        event["userIdentity"].pop("arn")

        with self.assertRaisesRegex(ValueError, "no recipientAccountId"):
            normalize_aws_cloudtrail_environment(({"Records": [event]},))

    def test_account_identifiers_and_identity_consistency_are_validated(self):
        event = _event()
        event["recipientAccountId"] = "account"
        with self.assertRaisesRegex(ValueError, "recipientAccountId must be a 12-digit"):
            normalize_aws_cloudtrail_environment(({"Records": [event]},))

        event = _event()
        event["userIdentity"]["accountId"] = "account"
        with self.assertRaisesRegex(ValueError, "userIdentity accountId must be a 12-digit"):
            normalize_aws_cloudtrail_environment(({"Records": [event]},))

        event = _event()
        event["userIdentity"]["arn"] = "arn:aws:iam::999988887777:user/alice"
        with self.assertRaisesRegex(ValueError, "does not match its ARN account"):
            normalize_aws_cloudtrail_environment(({"Records": [event]},))

    def test_event_version_format_and_major_are_validated(self):
        for version, message in (
            ("one", "major.minor"),
            ("1", "major.minor"),
            ("2.0", "unsupported"),
        ):
            with self.subTest(version=version):
                event = _event()
                event["eventVersion"] = version
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_cloudtrail_environment(({"Records": [event]},))

    def test_event_time_must_be_valid_utc(self):
        for event_time, message in (
            ("not-a-time", "ISO 8601"),
            ("2026-06-30T01:00:00", "must use UTC"),
            ("2026-06-30T11:00:00+10:00", "must use UTC"),
        ):
            with self.subTest(event_time=event_time):
                event = _event()
                event["eventTime"] = event_time
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_cloudtrail_environment(({"Records": [event]},))

    def test_event_id_must_be_guid(self):
        event = _event("not-a-guid")

        with self.assertRaisesRegex(ValueError, "CloudTrail GUID"):
            normalize_aws_cloudtrail_environment(({"Records": [event]},))

    def test_required_event_strings_and_identity_are_validated(self):
        for field in ("eventSource", "eventName", "awsRegion", "sourceIPAddress"):
            with self.subTest(field=field):
                event = _event()
                event[field] = ""
                with self.assertRaisesRegex(ValueError, field):
                    normalize_aws_cloudtrail_environment(({"Records": [event]},))

        event = _event()
        event["userIdentity"] = []
        with self.assertRaisesRegex(ValueError, "userIdentity must be an object"):
            normalize_aws_cloudtrail_environment(({"Records": [event]},))

        event = _event()
        event["userIdentity"]["type"] = ""
        with self.assertRaisesRegex(ValueError, "type"):
            normalize_aws_cloudtrail_environment(({"Records": [event]},))

    def test_optional_event_fields_are_validated(self):
        cases = (
            ("requestParameters", [], "object or null"),
            ("responseElements", "success", "object or null"),
            ("additionalEventData", [], "object or null"),
            ("errorCode", 403, "non-empty string"),
            ("errorMessage", {}, "must be a string"),
            ("userAgent", {}, "non-empty string"),
            ("requestID", 123, "non-empty string"),
            ("eventType", "", "non-empty string"),
            ("eventCategory", "Insight", "unsupported eventCategory"),
            ("readOnly", "false", "must be a boolean"),
            ("managementEvent", 1, "must be a boolean"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                event = _event()
                event[field] = value
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_cloudtrail_environment(({"Records": [event]},))

    def test_records_container_and_inputs_are_validated(self):
        for payload in ({}, {"Records": {}}, {"Records": []}, {"Records": ["event"]}):
            with self.subTest(payload=payload), self.assertRaisesRegex(
                ValueError, "Records"
            ):
                normalize_aws_cloudtrail_environment((payload,))

        with self.assertRaisesRegex(ValueError, "At least one"):
            normalize_aws_cloudtrail_environment(())
        with self.assertRaisesRegex(ValueError, "At least one"):
            load_aws_cloudtrail_environment(())

    def test_file_and_event_resource_limits_are_enforced(self):
        with self.assertRaisesRegex(
            ValueError,
            r"contains 101 files; limit is 100",
        ):
            load_aws_cloudtrail_environment(
                tuple(Path(f"event-{index}.json") for index in range(101))
            )

        with self.assertRaisesRegex(
            ValueError,
            r"event input contains 10,001 items; limit is 10,000",
        ):
            normalize_aws_cloudtrail_environment(
                ({"Records": [{}] * 10_001},)
            )

    def test_loader_rejects_non_object_and_corrupt_gzip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "events.json"
            json_path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must contain a JSON object"):
                load_aws_cloudtrail_environment((json_path,))

            gzip_path = Path(tmpdir) / "events.json.gz"
            gzip_path.write_bytes(b"not-gzip")
            with self.assertRaisesRegex(ValueError, "not valid gzip"):
                load_aws_cloudtrail_environment((gzip_path,))

            truncated_gzip_path = Path(tmpdir) / "truncated.json.gz"
            truncated_gzip_path.write_bytes(
                gzip.compress(json.dumps({"Records": [_event()]}).encode())[:-4]
            )
            with self.assertRaisesRegex(ValueError, "not valid gzip"):
                load_aws_cloudtrail_environment((truncated_gzip_path,))

            invalid_utf8_path = Path(tmpdir) / "invalid.json"
            invalid_utf8_path.write_bytes(b"\xff")
            with self.assertRaisesRegex(ValueError, "not valid UTF-8"):
                load_aws_cloudtrail_environment((invalid_utf8_path,))

            invalid_json_path = Path(tmpdir) / "malformed.json"
            invalid_json_path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not contain valid JSON"):
                load_aws_cloudtrail_environment((invalid_json_path,))

    def test_loader_reads_gzip_payload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "events.json.gz"
            with gzip.open(path, "wt", encoding="utf-8") as handle:
                json.dump({"Records": [_event()]}, handle)

            result = load_aws_cloudtrail_environment((path,))

        self.assertEqual(1, len(result.environment["events"]))


if __name__ == "__main__":
    unittest.main()
