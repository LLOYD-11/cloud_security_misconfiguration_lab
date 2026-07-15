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


if __name__ == "__main__":
    unittest.main()
