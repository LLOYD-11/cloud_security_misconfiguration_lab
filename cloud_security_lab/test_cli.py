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
            summary_path = Path(tmpdir) / "iam-summary.json"
            with redirect_stdout(StringIO()):
                result = main(
                    [
                        "analyze",
                        "iam",
                        str(PROJECT_ROOT / "sample_data/iam/sample_iam_environment.json"),
                        "--output",
                        str(output_path),
                        "--summary-output",
                        str(summary_path),
                    ]
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual(9, payload["finding_count"])
        self.assertEqual("2.0", payload["schema_version"])
        self.assertTrue(
            all(
                finding["account_id"] == "111122223333"
                and finding["region"] == "global"
                and finding["finding_id"].startswith("FND-")
                and finding["evidence_references"]
                for finding in payload["findings"]
            )
        )
        self.assertEqual("complete", summary["coverage_status"])
        self.assertEqual("simplified", summary["input_format"])
        self.assertEqual(
            ["group", "role", "root-account", "user"],
            [item["resource_type"] for item in summary["resource_coverage"]],
        )

    def test_analyze_native_aws_iam_writes_findings_and_normalized_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "iam.json"
            normalized_path = Path(tmpdir) / "normalized-iam.json"
            summary_path = Path(tmpdir) / "iam-summary.json"
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
                        "--observed-at",
                        "2026-06-30T00:00:00+00:00",
                        "--summary-output",
                        str(summary_path),
                    ]
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            normalized = json.loads(normalized_path.read_text(encoding="utf-8"))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual("", stderr.getvalue())
        self.assertEqual(9, payload["finding_count"])
        self.assertEqual("111122223333", normalized["account_id"])
        self.assertTrue(
            all(
                finding["observed_at"] == "2026-06-30T00:00:00Z"
                for finding in payload["findings"]
            )
        )
        self.assertEqual(
            {
                "as_of": "2026-06-30",
                "observed_at": "2026-06-30T00:00:00Z",
            },
            summary["parameters"],
        )

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
        self.assertEqual(7, payload["finding_count"])
        self.assertEqual(3, len(normalized["buckets"]))
        self.assertTrue(
            all(
                finding["account_id"] == "111122223333"
                and finding["region"] == "ap-southeast-2"
                for finding in payload["findings"]
            )
        )

    def test_analyze_native_aws_ec2_writes_findings_and_normalized_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "network.json"
            normalized_path = Path(tmpdir) / "normalized-network.json"
            summary_path = Path(tmpdir) / "network-summary.json"
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
                        "--reachability-context",
                        str(
                            PROJECT_ROOT
                            / "sample_data/aws/ec2/network_reachability_context.json"
                        ),
                        "--normalized-output",
                        str(normalized_path),
                        "--region",
                        "ap-southeast-2",
                        "--observed-at",
                        "2026-06-30T04:00:00Z",
                        "--output",
                        str(output_path),
                        "--summary-output",
                        str(summary_path),
                    ]
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            normalized = json.loads(normalized_path.read_text(encoding="utf-8"))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual(10, payload["finding_count"])
        self.assertTrue(
            all(
                finding["region"] == "ap-southeast-2"
                for finding in payload["findings"]
            )
        )
        self.assertEqual(
            {
                "2026-06-30T04:00:00Z",
                "2026-06-30T04:05:00Z",
                "2026-06-30T04:10:00Z",
            },
            {finding["observed_at"] for finding in payload["findings"]},
        )
        self.assertEqual(4, len(normalized["security_groups"]))
        self.assertEqual(
            "reachable",
            normalized["security_groups"][0]["reachability"]["ingress"]["status"],
        )
        self.assertTrue(
            all(
                "reachability_status" in finding["metadata"]
                for finding in payload["findings"]
            )
        )
        self.assertIn("prefix-list targets", stderr.getvalue())
        self.assertIn("security-group targets", stderr.getvalue())
        self.assertEqual("partial", summary["coverage_status"])
        self.assertEqual(2, summary["input_file_count"])
        self.assertEqual("ap-southeast-2", summary["parameters"]["region"])
        self.assertEqual(
            "2026-06-30T04:00:00Z",
            summary["parameters"]["observed_at"],
        )
        self.assertEqual(
            {
                "NET_PREFIX_LIST_TARGET_UNRESOLVED",
                "NET_SECURITY_GROUP_TARGET_UNRESOLVED",
            },
            {item["code"] for item in summary["skipped_evidence"]},
        )

    def test_simplified_network_context_replaces_embedded_context_set(self):
        sample_path = (
            PROJECT_ROOT / "sample_data/network/sample_network_environment.json"
        )
        environment = json.loads(sample_path.read_text(encoding="utf-8"))
        first_group = environment["security_groups"][0]
        context_payload = {
            "schema_version": "1.0",
            "security_groups": [
                {
                    "group_id": first_group["id"],
                    **first_group["reachability"],
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            context_path = Path(tmpdir) / "reachability.json"
            output_path = Path(tmpdir) / "network.json"
            context_path.write_text(json.dumps(context_payload), encoding="utf-8")
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as stderr:
                result = main(
                    [
                        "analyze",
                        "network",
                        str(sample_path),
                        "--reachability-context",
                        str(context_path),
                        "--output",
                        str(output_path),
                    ]
                )
            findings = json.loads(output_path.read_text(encoding="utf-8"))["findings"]

        self.assertEqual(0, result)
        self.assertIn("3 security group(s)", stderr.getvalue())
        statuses_by_group = {
            finding["resource_id"]: finding["metadata"]["reachability_status"]
            for finding in findings
        }
        self.assertEqual("reachable", statuses_by_group["sg-001-admin-open"])
        self.assertEqual("not_assessed", statuses_by_group["sg-002-database-public"])
        self.assertEqual("not_assessed", statuses_by_group["sg-003-all-open"])

    def test_analyze_native_cloudtrail_merges_json_and_gzip_inputs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "cloudtrail.json"
            incidents_path = Path(tmpdir) / "cloudtrail-incidents.json"
            normalized_path = Path(tmpdir) / "normalized-cloudtrail.json"
            summary_path = Path(tmpdir) / "cloudtrail-summary.json"
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
                        "--incidents-output",
                        str(incidents_path),
                        "--summary-output",
                        str(summary_path),
                    ]
                )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            incidents = json.loads(incidents_path.read_text(encoding="utf-8"))
            normalized = json.loads(normalized_path.read_text(encoding="utf-8"))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual(11, payload["finding_count"])
        self.assertEqual(2, incidents["incident_count"])
        self.assertEqual(17, len(normalized["events"]))
        self.assertIn("Skipped 1 duplicate", stderr.getvalue())
        self.assertEqual("complete", summary["coverage_status"])
        self.assertEqual(
            {
                "discovered_count": 18,
                "evaluated_count": 17,
                "resource_type": "event",
                "skipped_count": 1,
            },
            summary["resource_coverage"][0],
        )
        self.assertFalse(summary["skipped_evidence"][0]["affects_coverage"])
        self.assertEqual(
            {
                "correlation_window_minutes": "30",
                "failure_threshold": "5",
                "failure_window_minutes": "10",
            },
            summary["parameters"],
        )

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
            timeline = json.loads(
                (output_dir / "attack_timeline.json").read_text(encoding="utf-8")
            )
            generated_names = {path.name for path in output_dir.iterdir()}

        self.assertEqual(0, result)
        self.assertIn("Generated: 2026-06-30", report)
        self.assertIn("consolidates 39 findings", report)
        self.assertIn("## Analysis Coverage", report)
        self.assertIn("| cloudtrail | simplified (1 file(s)) | complete |", report)
        self.assertIn("## Prioritized Remediation Plan", report)
        self.assertIn("| **P0** |", report)
        self.assertIn("## Attack Timeline", report)
        self.assertEqual(11, timeline["entry_count"])
        self.assertEqual(0, timeline["omission_count"])
        self.assertIn("## Correlated Incidents", report)
        self.assertEqual(
            {
                "attack_timeline.json",
                "cloud_security_report.md",
                "cloudtrail_analysis_summary.json",
                "cloudtrail_incidents.json",
                "cloudtrail_findings.json",
                "iam_analysis_summary.json",
                "iam_findings.json",
                "network_analysis_summary.json",
                "network_findings.json",
                "remediation_plan.json",
                "storage_analysis_summary.json",
                "storage_findings.json",
            },
            generated_names,
        )

    def test_report_subcommand_reads_versioned_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_path = Path(tmpdir) / "iam.json"
            report_path = Path(tmpdir) / "report.md"
            remediation_path = Path(tmpdir) / "remediation.json"
            timeline_path = Path(tmpdir) / "timeline.json"
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
                        "--remediation-output",
                        str(remediation_path),
                        "--timeline-output",
                        str(timeline_path),
                    ]
                )
            report = report_path.read_text(encoding="utf-8")
            remediation = json.loads(
                remediation_path.read_text(encoding="utf-8")
            )
            timeline = json.loads(timeline_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertIn("consolidates 9 findings", report)
        self.assertEqual(9, remediation["source_finding_count"])
        self.assertEqual(0, remediation["source_incident_count"])
        self.assertGreater(remediation["action_count"], 0)
        self.assertEqual(0, timeline["source_cloudtrail_finding_count"])
        self.assertEqual(0, timeline["entry_count"])

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

    def test_cloudtrail_summary_records_custom_analysis_parameters(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            summary_path = Path(tmpdir) / "summary.json"
            with redirect_stdout(StringIO()):
                result = main(
                    [
                        "analyze",
                        "cloudtrail",
                        str(
                            PROJECT_ROOT
                            / "sample_data/cloudtrail/sample_cloudtrail_events.json"
                        ),
                        "--failure-threshold",
                        "4",
                        "--failure-window-minutes",
                        "8",
                        "--correlation-window-minutes",
                        "20",
                        "--summary-output",
                        str(summary_path),
                    ]
                )
            summary = json.loads(summary_path.read_text(encoding="utf-8"))

        self.assertEqual(0, result)
        self.assertEqual(
            {
                "correlation_window_minutes": "20",
                "failure_threshold": "4",
                "failure_window_minutes": "8",
            },
            summary["parameters"],
        )

    def test_cloudtrail_incident_options_are_rejected_for_other_modules(self):
        with redirect_stderr(StringIO()) as stderr, self.assertRaises(
            SystemExit
        ) as context:
            main(
                [
                    "analyze",
                    "iam",
                    str(PROJECT_ROOT / "sample_data/iam/sample_iam_environment.json"),
                    "--incidents-output",
                    "incidents.json",
                ]
            )

        self.assertEqual(2, context.exception.code)
        self.assertIn("only valid for cloudtrail", stderr.getvalue())

    def test_analyze_rejects_non_rfc3339_observed_at(self):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as context:
            main(
                [
                    "analyze",
                    "iam",
                    str(
                        PROJECT_ROOT
                        / "sample_data/iam/sample_iam_environment.json"
                    ),
                    "--observed-at",
                    "2026-06-30T00:00:00+0000",
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

    def test_reachability_context_is_rejected_for_other_modules(self):
        with redirect_stderr(StringIO()) as stderr, self.assertRaises(
            SystemExit
        ) as context:
            main(
                [
                    "analyze",
                    "storage",
                    str(PROJECT_ROOT / "sample_data/storage/sample_storage_environment.json"),
                    "--reachability-context",
                    str(
                        PROJECT_ROOT
                        / "sample_data/aws/ec2/network_reachability_context.json"
                    ),
                ]
            )

        self.assertEqual(2, context.exception.code)
        self.assertIn("only valid for network analysis", stderr.getvalue())

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

    def test_catalog_defaults_to_markdown_stdout(self):
        stdout = StringIO()
        with redirect_stdout(stdout):
            result = main(["catalog", "--module", "network"])

        output = stdout.getvalue()
        self.assertEqual(0, result)
        self.assertIn("# Detection Rule Catalog", output)
        self.assertIn("## Network", output)
        self.assertIn("`NET-001`", output)
        self.assertNotIn("`IAM-001`", output)

    def test_catalog_json_filter_has_consistent_count(self):
        stdout = StringIO()
        with redirect_stdout(stdout):
            result = main(
                ["catalog", "--module", "storage", "--format", "json"]
            )
        payload = json.loads(stdout.getvalue())

        self.assertEqual(0, result)
        self.assertEqual("1.0", payload["schema_version"])
        self.assertEqual(6, payload["rule_count"])
        self.assertTrue(
            all(rule["module"] == "storage" for rule in payload["rules"])
        )

    def test_catalog_writes_requested_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "docs" / "catalog.md"
            with redirect_stdout(StringIO()) as stdout:
                result = main(["catalog", "--output", str(output_path)])
            output = output_path.read_text(encoding="utf-8")

        self.assertEqual(0, result)
        self.assertIn("Rule catalog saved", stdout.getvalue())
        self.assertIn("### CLD-011", output)


if __name__ == "__main__":
    unittest.main()
