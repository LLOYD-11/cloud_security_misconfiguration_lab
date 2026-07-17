import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from cloud_analysis import (
    AnalysisSummary,
    ResourceCoverage,
    SkippedEvidence,
    analysis_summary_from_dict,
    load_analysis_summary_file,
    write_analysis_summary,
)


def _summary(**overrides):
    values = {
        "module": "iam",
        "analyzer_version": "2.0.0",
        "input_format": "aws",
        "input_file_count": 2,
        "coverage_status": "partial",
        "finding_count": 3,
        "incident_count": 0,
        "parameters": {"as_of": "2026-06-30"},
        "resource_coverage": [
            ResourceCoverage(
                resource_type="user",
                discovered_count=2,
                evaluated_count=2,
                skipped_count=0,
            )
        ],
        "skipped_evidence": [
            SkippedEvidence(
                code="IAM_POLICY_DOCUMENT_ABSENT",
                evidence_type="managed-policy-document",
                reason="A referenced policy document was not present.",
                count=1,
                affects_coverage=True,
                resource_ids=["arn:aws:iam::111122223333:policy/missing"],
            )
        ],
        "warnings": ["One policy document was not available."],
    }
    values.update(overrides)
    return AnalysisSummary(**values)


class AnalysisSummaryTests(unittest.TestCase):
    def test_round_trip_preserves_versioned_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "summary.json"
            write_analysis_summary(path, _summary())
            payload = json.loads(path.read_text(encoding="utf-8"))
            loaded = load_analysis_summary_file(path)

        self.assertEqual("1.0", payload["schema_version"])
        self.assertEqual("partial", loaded.coverage_status)
        self.assertEqual(2, loaded.resource_coverage[0].evaluated_count)

    def test_empty_status_requires_no_evaluated_resources(self):
        summary = _summary(
            coverage_status="empty",
            resource_coverage=[
                ResourceCoverage(
                    resource_type="user",
                    discovered_count=0,
                    evaluated_count=0,
                    skipped_count=0,
                )
            ],
            skipped_evidence=[],
        )
        self.assertEqual("empty", summary.coverage_status)

        with self.assertRaisesRegex(ValueError, "coverage_status is inconsistent"):
            _summary(coverage_status="empty")

    def test_non_gap_skip_keeps_complete_status(self):
        summary = _summary(
            module="cloudtrail",
            input_file_count=1,
            coverage_status="complete",
            resource_coverage=[
                ResourceCoverage(
                    resource_type="event",
                    discovered_count=2,
                    evaluated_count=1,
                    skipped_count=1,
                )
            ],
            skipped_evidence=[
                SkippedEvidence(
                    code="CLD_DUPLICATE_EVENT",
                    evidence_type="cloudtrail-event",
                    reason="An identical duplicate event was analyzed once.",
                    count=1,
                    affects_coverage=False,
                    resource_ids=["event-1"],
                )
            ],
        )
        self.assertEqual("complete", summary.coverage_status)

    def test_resource_counts_must_balance(self):
        with self.assertRaisesRegex(ValueError, "must equal"):
            ResourceCoverage(
                resource_type="bucket",
                discovered_count=3,
                evaluated_count=1,
                skipped_count=1,
            )

    def test_loader_rejects_unknown_version_and_count_types(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "summary.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "999.0",
                        "module": "iam",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unsupported"):
                load_analysis_summary_file(path)

        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            _summary(finding_count=True)

    def test_summary_requires_deterministic_resource_and_skip_order(self):
        with self.assertRaisesRegex(ValueError, "sorted by resource_type"):
            _summary(
                resource_coverage=[
                    ResourceCoverage("user", 1, 1, 0),
                    ResourceCoverage("group", 1, 1, 0),
                ]
            )

    def test_writer_canonicalizes_parameter_key_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "summary.json"
            write_analysis_summary(
                path,
                _summary(parameters={"z": "last", "a": "first"}),
            )
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(["a", "z"], list(payload["parameters"]))

    def test_resource_and_skipped_evidence_values_are_strict(self):
        resource_cases = (
            (("", 1, 1, 0), "resource_type"),
            (("bucket", -1, 0, 0), "non-negative"),
            (("bucket", True, 1, 0), "non-negative"),
        )
        for values, message in resource_cases:
            with self.subTest(values=values), self.assertRaisesRegex(
                ValueError, message
            ):
                ResourceCoverage(*values)

        base = SkippedEvidence(
            code="IAM_GAP",
            evidence_type="policy",
            reason="Evidence was absent.",
            count=1,
            affects_coverage=True,
            resource_ids=["resource-1"],
        )
        skipped_cases = (
            ({"code": "iam-gap"}, "uppercase"),
            ({"evidence_type": ""}, "evidence_type"),
            ({"reason": ""}, "reason"),
            ({"count": 0}, "positive"),
            ({"affects_coverage": 1}, "boolean"),
            ({"resource_ids": [""]}, "non-empty"),
            ({"resource_ids": ["a", "a"]}, "duplicates"),
            ({"resource_ids": ["a", "b"]}, "lower"),
        )
        for changes, message in skipped_cases:
            with self.subTest(changes=changes), self.assertRaisesRegex(
                ValueError, message
            ):
                replace(base, **changes)

    def test_summary_rejects_invalid_top_level_values(self):
        cases = (
            ({"module": "compute"}, "module"),
            ({"analyzer_version": ""}, "analyzer_version"),
            ({"input_format": "live"}, "input_format"),
            ({"input_file_count": 0}, "positive"),
            ({"coverage_status": "unknown"}, "coverage_status"),
            ({"incident_count": -1}, "non-negative"),
            ({"parameters": {"key": 1}}, "parameters"),
            ({"resource_coverage": ["user"]}, "ResourceCoverage"),
            (
                {
                    "resource_coverage": [
                        ResourceCoverage("user", 1, 1, 0),
                        ResourceCoverage("user", 2, 2, 0),
                    ]
                },
                "repeat resource types",
            ),
            ({"skipped_evidence": ["gap"]}, "SkippedEvidence"),
            ({"warnings": [""]}, "non-empty strings"),
            ({"warnings": ["same", "same"]}, "duplicates"),
        )
        for changes, message in cases:
            with self.subTest(changes=changes), self.assertRaisesRegex(
                ValueError, message
            ):
                _summary(**changes)

    def test_dict_loader_rejects_malformed_top_level_and_nested_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "summary.json"
            write_analysis_summary(path, _summary())
            payload = json.loads(path.read_text(encoding="utf-8"))
        payload.pop("schema_version")

        malformed_cases = (
            ([], "JSON object"),
            ({key: value for key, value in payload.items() if key != "module"}, "missing"),
            ({**payload, "extra": True}, "unsupported"),
            ({**payload, "parameters": []}, "parameters"),
            ({**payload, "resource_coverage": {}}, "resource_coverage"),
            ({**payload, "skipped_evidence": {}}, "skipped_evidence"),
            ({**payload, "warnings": {}}, "warnings"),
            ({**payload, "resource_coverage": ["entry"]}, "JSON object"),
            (
                {
                    **payload,
                    "resource_coverage": [
                        {
                            "resource_type": "user",
                            "discovered_count": 1,
                            "evaluated_count": 1,
                        }
                    ],
                },
                "missing fields",
            ),
            (
                {
                    **payload,
                    "resource_coverage": [
                        {
                            "resource_type": "user",
                            "discovered_count": 1,
                            "evaluated_count": 1,
                            "skipped_count": 0,
                            "extra": True,
                        }
                    ],
                },
                "unsupported fields",
            ),
            ({**payload, "skipped_evidence": ["entry"]}, "JSON object"),
            (
                {
                    **payload,
                    "skipped_evidence": [
                        {
                            "code": "IAM_GAP",
                            "evidence_type": "policy",
                            "reason": "Missing.",
                            "count": 1,
                            "affects_coverage": True,
                        }
                    ],
                },
                "missing fields",
            ),
            (
                {
                    **payload,
                    "skipped_evidence": [
                        {
                            "code": "IAM_GAP",
                            "evidence_type": "policy",
                            "reason": "Missing.",
                            "count": 1,
                            "affects_coverage": True,
                            "resource_ids": [],
                            "extra": True,
                        }
                    ],
                },
                "unsupported fields",
            ),
        )
        for candidate, message in malformed_cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                ValueError, message
            ):
                analysis_summary_from_dict(candidate)

        with self.assertRaisesRegex(ValueError, "deterministic order"):
            _summary(
                skipped_evidence=[
                    SkippedEvidence("IAM_Z", "policy", "Missing Z.", 1, True),
                    SkippedEvidence("IAM_A", "policy", "Missing A.", 1, True),
                ]
            )


if __name__ == "__main__":
    unittest.main()
