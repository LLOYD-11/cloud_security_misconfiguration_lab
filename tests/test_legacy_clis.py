import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from cloud_findings import Finding, write_findings
from cloudtrail_detector.detector import main as cloudtrail_main
from iam_analyzer.analyzer import main as iam_main
from network_analyzer.analyzer import main as network_main
from report_generator.generate_report import main as report_main
from storage_analyzer.analyzer import main as storage_main

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ANALYZER_CASES = (
    (iam_main, "sample_data/iam/sample_iam_environment.json", 9),
    (storage_main, "sample_data/storage/sample_storage_environment.json", 9),
    (network_main, "sample_data/network/sample_network_environment.json", 10),
    (cloudtrail_main, "sample_data/cloudtrail/sample_cloudtrail_events.json", 11),
)


class LegacyCliCompatibilityTests(unittest.TestCase):
    def test_module_script_entrypoints_still_export_expected_findings(self):
        for entrypoint, sample_name, expected_count in ANALYZER_CASES:
            with self.subTest(sample=sample_name), tempfile.TemporaryDirectory() as tmpdir:
                output_path = Path(tmpdir) / "findings.json"
                argv = [
                    "analyzer",
                    str(PROJECT_ROOT / sample_name),
                    "--output",
                    str(output_path),
                ]
                with patch.object(sys, "argv", argv), redirect_stdout(StringIO()):
                    result = entrypoint()
                payload = json.loads(output_path.read_text(encoding="utf-8"))

                self.assertEqual(0, result)
                self.assertEqual(expected_count, payload["finding_count"])

    def test_cloudtrail_script_rejects_conflicting_event_ids(self):
        event = {
            "eventID": "duplicate-event",
            "eventTime": "2026-06-30T01:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "sourceIPAddress": "192.0.2.1",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
            "requestParameters": {"bucketName": "example"},
        }
        conflicting = {
            **event,
            "eventName": "GetBucketPolicy",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "conflicting-events.json"
            input_path.write_text(
                json.dumps({"events": [event, conflicting]}),
                encoding="utf-8",
            )
            argv = ["cloudtrail_detector", str(input_path)]
            stderr = StringIO()

            with patch.object(sys, "argv", argv), redirect_stdout(
                StringIO()
            ), redirect_stderr(stderr), self.assertRaises(SystemExit) as context:
                cloudtrail_main()

        self.assertEqual(2, context.exception.code)
        self.assertIn(
            "Conflicting CloudTrail events share eventID 'duplicate-event'",
            stderr.getvalue(),
        )

    def test_report_script_entrypoint_still_writes_markdown(self):
        finding = Finding(
            rule_id="TEST-001",
            severity="low",
            module="test",
            category="compatibility",
            resource_type="resource",
            resource_id="example",
            title="Compatibility finding",
            evidence="Evidence",
            impact="Impact",
            remediation="Remediation",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            findings_path = Path(tmpdir) / "findings.json"
            report_path = Path(tmpdir) / "report.md"
            write_findings(findings_path, [finding])
            argv = [
                "generate_report",
                "--findings",
                str(findings_path),
                "--output",
                str(report_path),
                "--report-date",
                "2026-06-30",
            ]
            with patch.object(sys, "argv", argv), redirect_stdout(StringIO()):
                result = report_main()
            report = report_path.read_text(encoding="utf-8")

        self.assertEqual(0, result)
        self.assertIn("Generated: 2026-06-30", report)
        self.assertIn("TEST-001", report)


if __name__ == "__main__":
    unittest.main()
