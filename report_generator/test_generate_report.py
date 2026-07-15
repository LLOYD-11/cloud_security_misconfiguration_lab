import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from cloud_findings import Finding, load_findings_file, write_findings
from report_generator.generate_report import (
    build_parser,
    load_all_findings,
    render_report,
    write_report,
)


class ReportGeneratorTests(unittest.TestCase):
    def test_load_all_findings_merges_files(self):
        finding_a = Finding(
            rule_id="IAM-001",
            severity="critical",
            module="iam",
            category="identity-and-access",
            resource_type="user",
            resource_id="alice-admin",
            title="Administrator-style wildcard permission",
            evidence='Action "*" on Resource "*".',
            impact="Full administrative access may be available.",
            remediation="Use least privilege.",
        )
        finding_b = Finding(
            rule_id="STO-001",
            severity="high",
            module="storage",
            category="data-exposure",
            resource_type="bucket",
            resource_id="public-logs",
            title="Public bucket policy",
            evidence='Bucket policy allows Principal "*".',
            impact="Data may be publicly readable.",
            remediation="Restrict the bucket policy.",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path_a = Path(tmpdir) / "iam.json"
            path_b = Path(tmpdir) / "storage.json"
            write_findings(path_a, [finding_a])
            write_findings(path_b, [finding_b])

            findings = load_all_findings([path_a, path_b])

        self.assertEqual(["IAM-001", "STO-001"], [finding.rule_id for finding in findings])

    def test_render_report_includes_summary_and_details(self):
        finding = Finding(
            rule_id="IAM-008",
            severity="high",
            module="iam",
            category="identity-and-access",
            resource_type="role",
            resource_id="third-party-audit-role",
            title="Cross-account role trust",
            evidence="Trust policy allows an external principal.",
            impact="External account may assume the role.",
            remediation="Restrict trusted principals and require external ID.",
            references=["https://attack.mitre.org/techniques/T1199/"],
            metadata={"policy_name": "trust-policy", "statement_id": "ExternalTrust"},
        )

        report = render_report(
            [finding],
            source_files=[Path("reports/generated/iam_findings.json")],
            report_date=date(2026, 6, 30),
        )

        self.assertIn("# Cloud Security Risk Report", report)
        self.assertIn("| High | 1 |", report)
        self.assertIn("| iam | 1 |", report)
        self.assertIn("#### IAM-008: Cross-account role trust", report)
        self.assertIn("policy_name: trust-policy", report)
        self.assertIn("https://attack.mitre.org/techniques/T1199/", report)

    def test_write_report_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "nested" / "report.md"
            write_report(output_path, "# Report\n")

            self.assertEqual("# Report\n", output_path.read_text(encoding="utf-8"))

    def test_parser_accepts_explicit_report_date(self):
        args = build_parser().parse_args(
            [
                "--findings",
                "findings.json",
                "--output",
                "report.md",
                "--report-date",
                "2026-06-30",
            ]
        )

        self.assertEqual(date(2026, 6, 30), args.report_date)

    def test_finding_rejects_unknown_severity(self):
        with self.assertRaisesRegex(ValueError, "severity"):
            Finding(
                rule_id="TEST-001",
                severity="urgent",
                module="test",
                category="test",
                resource_type="resource",
                resource_id="example",
                title="Invalid severity",
                evidence="Evidence",
                impact="Impact",
                remediation="Remediation",
            )

    def test_loader_rejects_unknown_schema_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "findings.json"
            path.write_text(
                '{"schema_version":"999.0","finding_count":0,"findings":[]}\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "schema version"):
                load_findings_file(path)

    def test_loader_rejects_incorrect_finding_count(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "findings.json"
            path.write_text(
                '{"schema_version":"1.0","finding_count":1,"findings":[]}\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "finding_count"):
                load_findings_file(path)

    def test_loader_rejects_unversioned_legacy_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "findings.json"
            path.write_text("[]\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "versioned"):
                load_findings_file(path)

    def test_loader_rejects_non_string_finding_values(self):
        valid_finding = {
            "rule_id": "TEST-001",
            "severity": "high",
            "module": "test",
            "category": "test",
            "resource_type": "resource",
            "resource_id": "example",
            "title": "Example finding",
            "evidence": "Evidence",
            "impact": "Impact",
            "remediation": "Remediation",
            "references": ["https://example.com/reference"],
            "metadata": {"source": "test"},
        }
        invalid_values = (
            ("rule_id", 101, "rule_id"),
            ("severity", 3, "severity"),
            ("references", [42], "references"),
            ("metadata", {"attempts": 5}, "metadata"),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "findings.json"
            for field_name, invalid_value, error_pattern in invalid_values:
                with self.subTest(field_name=field_name):
                    finding = dict(valid_finding)
                    finding[field_name] = invalid_value
                    path.write_text(
                        json.dumps(
                            {
                                "schema_version": "1.0",
                                "finding_count": 1,
                                "findings": [finding],
                            }
                        ),
                        encoding="utf-8",
                    )

                    with self.assertRaisesRegex(ValueError, error_pattern):
                        load_findings_file(path)


if __name__ == "__main__":
    unittest.main()
