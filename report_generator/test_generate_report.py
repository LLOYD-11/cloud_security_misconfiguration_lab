import json
import tempfile
import unittest
from dataclasses import replace
from datetime import date
from pathlib import Path

from cloud_analysis import (
    AnalysisSummary,
    ResourceCoverage,
    SkippedEvidence,
    write_analysis_summary,
)
from cloud_findings import Finding, load_findings_file, write_findings
from cloud_incidents import Incident, write_incidents
from report_generator.generate_report import (
    build_parser,
    load_all_analysis_summaries,
    load_all_findings,
    load_all_incidents,
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
        self.assertIn("## Prioritized Remediation Plan", report)
        self.assertIn("| **P2** |", report)
        self.assertIn("Restrict trusted principals and require external ID.", report)
        self.assertIn("## Triggered Rule Context", report)
        self.assertIn("MITRE ATT&CK Enterprise T1199 (related)", report)
        self.assertIn("#### IAM-008: Cross-account role trust", report)
        self.assertIn("policy_name: trust-policy", report)
        self.assertIn("https://attack.mitre.org/techniques/T1199/", report)

    def test_known_rule_context_rejects_wrong_module_or_severity(self):
        wrong_module = Finding(
            rule_id="IAM-001",
            severity="critical",
            module="storage",
            category="test",
            resource_type="bucket",
            resource_id="example",
            title="Wrong module",
            evidence="Synthetic evidence.",
            impact="Synthetic impact.",
            remediation="Synthetic remediation.",
        )
        with self.assertRaisesRegex(ValueError, "belongs to module iam"):
            render_report(
                [wrong_module],
                source_files=[],
                report_date=date(2026, 6, 30),
            )

        wrong_severity = replace(
            wrong_module,
            module="iam",
            severity="high",
        )
        with self.assertRaisesRegex(ValueError, "severity 'high' is not allowed"):
            render_report(
                [wrong_severity],
                source_files=[],
                report_date=date(2026, 6, 30),
            )

    def test_custom_rule_remains_report_compatible(self):
        custom = Finding(
            rule_id="CUSTOM-001",
            severity="info",
            module="custom",
            category="test",
            resource_type="fixture",
            resource_id="example",
            title="Custom extension rule",
            evidence="Synthetic evidence.",
            impact="Synthetic impact.",
            remediation="Synthetic remediation.",
        )

        report = render_report(
            [custom],
            source_files=[],
            report_date=date(2026, 6, 30),
        )

        self.assertIn("`CUSTOM-001`", report)
        self.assertIn("Not cataloged", report)

    def test_analysis_summary_replaces_finding_only_coverage(self):
        finding = Finding(
            rule_id="IAM-001",
            severity="critical",
            module="iam",
            category="identity-and-access",
            resource_type="user",
            resource_id="alice",
            title="Administrator access",
            evidence="Administrator policy observed.",
            impact="The user can control the account.",
            remediation="Apply least privilege.",
        )
        summary = AnalysisSummary(
            module="iam",
            analyzer_version="2.0.0.dev0",
            input_format="aws",
            input_file_count=2,
            coverage_status="partial",
            finding_count=1,
            incident_count=0,
            resource_coverage=[
                ResourceCoverage("user", 3, 3, 0),
            ],
            skipped_evidence=[
                SkippedEvidence(
                    code="IAM_POLICY_DOCUMENT_ABSENT",
                    evidence_type="managed-policy-document",
                    reason="One policy document was absent.",
                    count=1,
                    affects_coverage=True,
                    resource_ids=["missing-policy"],
                )
            ],
            warnings=["One policy attachment could not be resolved."],
        )

        report = render_report(
            [finding],
            source_files=[Path("iam.json"), Path("iam-summary.json")],
            report_date=date(2026, 6, 30),
            analysis_summaries=[summary],
        )

        self.assertIn("## Analysis Coverage", report)
        self.assertIn("| iam | aws (2 file(s)) | partial | user: 3/3 |", report)
        self.assertIn("`IAM_POLICY_DOCUMENT_ABSENT`", report)
        self.assertIn("### Analysis Warnings", report)
        self.assertNotIn("## Module Coverage", report)

    def test_analysis_summary_count_mismatch_is_rejected(self):
        summary = AnalysisSummary(
            module="iam",
            analyzer_version="2.0.0.dev0",
            input_format="simplified",
            input_file_count=1,
            coverage_status="complete",
            finding_count=1,
            incident_count=0,
            resource_coverage=[ResourceCoverage("user", 1, 1, 0)],
        )

        with self.assertRaisesRegex(ValueError, "declare 1 iam finding"):
            render_report(
                [],
                source_files=[],
                report_date=date(2026, 6, 30),
                analysis_summaries=[summary],
            )

    def test_partial_analysis_summary_set_is_rejected(self):
        iam_finding = Finding(
            rule_id="IAM-001",
            severity="critical",
            module="iam",
            category="identity-and-access",
            resource_type="user",
            resource_id="alice",
            title="Administrator access",
            evidence="Administrator policy observed.",
            impact="The user can control the account.",
            remediation="Apply least privilege.",
        )
        storage_finding = replace(
            iam_finding,
            rule_id="STO-001",
            module="storage",
            category="data-protection",
            resource_type="bucket",
            resource_id="example-bucket",
        )
        summary = AnalysisSummary(
            module="iam",
            analyzer_version="2.0.0.dev0",
            input_format="simplified",
            input_file_count=1,
            coverage_status="complete",
            finding_count=1,
            incident_count=0,
            resource_coverage=[ResourceCoverage("user", 1, 1, 0)],
        )

        with self.assertRaisesRegex(ValueError, "missing.*storage"):
            render_report(
                [iam_finding, storage_finding],
                source_files=[],
                report_date=date(2026, 6, 30),
                analysis_summaries=[summary],
            )

    def test_analysis_summary_files_load_in_module_order(self):
        summaries = [
            AnalysisSummary(
                module=module,
                analyzer_version="2.0.0.dev0",
                input_format="simplified",
                input_file_count=1,
                coverage_status="complete",
                finding_count=0,
                incident_count=0,
                resource_coverage=[ResourceCoverage(resource_type, 1, 1, 0)],
            )
            for module, resource_type in (
                ("storage", "bucket"),
                ("iam", "user"),
            )
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = []
            for summary in summaries:
                path = Path(tmpdir) / f"{summary.module}.json"
                write_analysis_summary(path, summary)
                paths.append(path)
            loaded = load_all_analysis_summaries(paths)

        self.assertEqual(["iam", "storage"], [item.module for item in loaded])

    def test_write_report_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "nested" / "report.md"
            write_report(output_path, "# Report\n")

            self.assertEqual("# Report\n", output_path.read_text(encoding="utf-8"))

    def test_load_and_render_correlated_incident(self):
        incident = Incident(
            incident_id="CTI-ABCDEF123456",
            severity="high",
            confidence="high",
            module="cloudtrail",
            category="correlated-activity",
            title="Identity protection weakened",
            actor="alice",
            source_ip="192.0.2.1",
            first_seen="2026-06-30T01:00:00Z",
            last_seen="2026-06-30T01:05:00Z",
            event_count=2,
            finding_count=2,
            rule_ids=["CLD-002", "CLD-005"],
            event_ids=["event-1", "event-2"],
            resources=["identity/alice", "iam_policy/example"],
            summary="Two related signals were observed.",
            recommended_actions=["Validate the activity."],
            references=["https://example.com/reference"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "incidents.json"
            write_incidents(path, [incident])
            incidents = load_all_incidents([path])

        report = render_report(
            [],
            source_files=[Path("reports/generated/cloudtrail_incidents.json")],
            report_date=date(2026, 6, 30),
            incidents=incidents,
        )

        self.assertIn("## Correlated Incidents", report)
        self.assertIn("| **P0** |", report)
        self.assertIn("Incident response", report)
        self.assertIn("CTI-ABCDEF123456", report)
        self.assertIn("CLD-002, CLD-005", report)
        self.assertIn("do not prove malicious intent", report)

    def test_parser_accepts_explicit_report_date(self):
        args = build_parser().parse_args(
            [
                "--findings",
                "findings.json",
                "--output",
                "report.md",
                "--incidents",
                "incidents.json",
                "--analysis-summary",
                "summary.json",
                "--report-date",
                "2026-06-30",
                "--remediation-output",
                "remediation.json",
            ]
        )

        self.assertEqual(date(2026, 6, 30), args.report_date)
        self.assertEqual([Path("incidents.json")], args.incidents)
        self.assertEqual([Path("summary.json")], args.analysis_summary)
        self.assertEqual(Path("remediation.json"), args.remediation_output)

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
