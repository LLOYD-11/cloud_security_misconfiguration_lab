import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from cloud_security_lab.cli import main

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class UnifiedCliTests(unittest.TestCase):
    def test_analyze_iam_matches_module_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "iam.json"
            with redirect_stdout(StringIO()):
                result = main(
                    [
                        "analyze",
                        "iam",
                        str(PROJECT_ROOT / "sample_data/iam/sample_iam_environment.json"),
                        "--output",
                        str(output_path),
                    ]
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual(8, payload["finding_count"])

    def test_analyze_native_aws_iam_writes_findings_and_normalized_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "iam.json"
            normalized_path = Path(tmpdir) / "normalized-iam.json"
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as stderr:
                result = main(
                    [
                        "analyze",
                        "iam",
                        str(
                            PROJECT_ROOT
                            / "sample_data/aws/iam/account_authorization_details.json"
                        ),
                        "--input-format",
                        "aws",
                        "--credential-report",
                        str(PROJECT_ROOT / "sample_data/aws/iam/credential_report.csv"),
                        "--as-of",
                        "2026-06-30",
                        "--normalized-output",
                        str(normalized_path),
                        "--output",
                        str(output_path),
                    ]
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            normalized = json.loads(normalized_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual("", stderr.getvalue())
        self.assertEqual(8, payload["finding_count"])
        self.assertEqual("111122223333", normalized["account_id"])

    def test_analyze_native_aws_s3_writes_findings_and_normalized_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "storage.json"
            normalized_path = Path(tmpdir) / "normalized-storage.json"
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as stderr:
                result = main(
                    [
                        "analyze",
                        "storage",
                        str(
                            PROJECT_ROOT
                            / "sample_data/aws/s3/s3_security_evidence_bundle.json"
                        ),
                        "--input-format",
                        "aws",
                        "--normalized-output",
                        str(normalized_path),
                        "--output",
                        str(output_path),
                    ]
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            normalized = json.loads(normalized_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual("", stderr.getvalue())
        self.assertEqual(5, payload["finding_count"])
        self.assertEqual(3, len(normalized["buckets"]))

    def test_analyze_native_aws_ec2_writes_findings_and_normalized_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "network.json"
            normalized_path = Path(tmpdir) / "normalized-network.json"
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as stderr:
                result = main(
                    [
                        "analyze",
                        "network",
                        str(
                            PROJECT_ROOT
                            / "sample_data/aws/ec2/describe_security_groups.json"
                        ),
                        "--input-format",
                        "aws",
                        "--normalized-output",
                        str(normalized_path),
                        "--output",
                        str(output_path),
                    ]
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            normalized = json.loads(normalized_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual(7, payload["finding_count"])
        self.assertEqual(4, len(normalized["security_groups"]))
        self.assertIn("prefix-list targets", stderr.getvalue())
        self.assertIn("security-group targets", stderr.getvalue())

    def test_analyze_native_cloudtrail_merges_json_and_gzip_inputs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "cloudtrail.json"
            normalized_path = Path(tmpdir) / "normalized-cloudtrail.json"
            sample_root = PROJECT_ROOT / "sample_data/aws/cloudtrail"
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as stderr:
                result = main(
                    [
                        "analyze",
                        "cloudtrail",
                        str(
                            sample_root
                            / "111122223333_CloudTrail_20260630T0200Z_part1.json"
                        ),
                        str(
                            sample_root
                            / "111122223333_CloudTrail_20260630T0300Z_part2.json.gz"
                        ),
                        "--input-format",
                        "aws",
                        "--normalized-output",
                        str(normalized_path),
                        "--output",
                        str(output_path),
                    ]
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            normalized = json.loads(normalized_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual(6, payload["finding_count"])
        self.assertEqual(12, len(normalized["events"]))
        self.assertIn("Skipped 1 duplicate", stderr.getvalue())

    def test_demo_runs_all_modules_and_writes_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "generated"
            with redirect_stdout(StringIO()):
                result = main(
                    [
                        "demo",
                        "--sample-root",
                        str(PROJECT_ROOT / "sample_data"),
                        "--output-dir",
                        str(output_dir),
                        "--report-date",
                        "2026-06-30",
                    ]
                )

            report = (output_dir / "cloud_security_report.md").read_text(encoding="utf-8")
            generated_names = {path.name for path in output_dir.iterdir()}

        self.assertEqual(0, result)
        self.assertIn("Generated: 2026-06-30", report)
        self.assertIn("consolidates 28 finding(s)", report)
        self.assertEqual(
            {
                "cloud_security_report.md",
                "cloudtrail_findings.json",
                "iam_findings.json",
                "network_findings.json",
                "storage_findings.json",
            },
            generated_names,
        )

    def test_report_subcommand_reads_versioned_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_path = Path(tmpdir) / "iam.json"
            report_path = Path(tmpdir) / "report.md"
            with redirect_stdout(StringIO()):
                main(
                    [
                        "analyze",
                        "iam",
                        str(PROJECT_ROOT / "sample_data/iam/sample_iam_environment.json"),
                        "--output",
                        str(findings_path),
                    ]
                )
                result = main(
                    [
                        "report",
                        "--findings",
                        str(findings_path),
                        "--output",
                        str(report_path),
                        "--report-date",
                        "2026-06-30",
                    ]
                )
            report = report_path.read_text(encoding="utf-8")

        self.assertEqual(0, result)
        self.assertIn("consolidates 8 finding(s)", report)

    def test_cloudtrail_threshold_options_are_rejected_for_other_modules(self):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as context:
            main(
                [
                    "analyze",
                    "iam",
                    str(PROJECT_ROOT / "sample_data/iam/sample_iam_environment.json"),
                    "--failure-threshold",
                    "3",
                ]
            )

        self.assertEqual(2, context.exception.code)

    def test_native_iam_requires_credential_report(self):
        with redirect_stderr(StringIO()) as stderr, self.assertRaises(SystemExit) as context:
            main(
                [
                    "analyze",
                    "iam",
                    str(
                        PROJECT_ROOT
                        / "sample_data/aws/iam/account_authorization_details.json"
                    ),
                    "--input-format",
                    "aws",
                ]
            )

        self.assertEqual(2, context.exception.code)
        self.assertIn("--credential-report is required", stderr.getvalue())

    def test_native_iam_options_are_rejected_for_other_modules(self):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as context:
            main(
                [
                    "analyze",
                    "storage",
                    str(PROJECT_ROOT / "sample_data/storage/sample_storage_environment.json"),
                    "--as-of",
                    "2026-06-30",
                ]
            )

        self.assertEqual(2, context.exception.code)

    def test_multiple_aws_inputs_are_rejected_for_non_cloudtrail_module(self):
        with redirect_stderr(StringIO()) as stderr, self.assertRaises(SystemExit) as context:
            path = PROJECT_ROOT / "sample_data/aws/ec2/describe_security_groups.json"
            main(
                [
                    "analyze",
                    "network",
                    str(path),
                    str(path),
                    "--input-format",
                    "aws",
                ]
            )

        self.assertEqual(2, context.exception.code)
        self.assertIn("only for the cloudtrail module", stderr.getvalue())

    def test_multiple_simplified_inputs_are_rejected(self):
        with redirect_stderr(StringIO()) as stderr, self.assertRaises(SystemExit) as context:
            path = PROJECT_ROOT / "sample_data/cloudtrail/sample_cloudtrail_events.json"
            main(["analyze", "cloudtrail", str(path), str(path)])

        self.assertEqual(2, context.exception.code)
        self.assertIn("exactly one JSON file", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
