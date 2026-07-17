import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from cloud_findings import (
    EvidenceReference,
    Finding,
    evidence_reference_ids,
    load_findings_file,
    sort_findings,
    with_finding_context,
    write_findings,
)


def _finding(**overrides):
    values = {
        "rule_id": "TEST-001",
        "severity": "high",
        "module": "test",
        "category": "test",
        "resource_type": "resource",
        "resource_id": "example",
        "title": "Example finding",
        "evidence": "Synthetic evidence.",
        "impact": "Synthetic impact.",
        "remediation": "Synthetic remediation.",
        "confidence": "medium",
        "account_id": "111122223333",
        "region": "ap-southeast-2",
        "observed_at": "2026-06-30T00:00:00Z",
        "evidence_references": [
            EvidenceReference(type="test-record", id="record-1")
        ],
    }
    values.update(overrides)
    return Finding(**values)


class FindingContractTests(unittest.TestCase):
    def test_stable_id_is_deterministic_and_uses_identity_context(self):
        first = _finding()
        second = _finding()
        changed = _finding(region="us-east-1")
        equivalent_timestamp = _finding(
            observed_at="2026-06-30T00:00:00+00:00"
        )

        self.assertRegex(first.finding_id, r"^FND-[0-9A-F]{32}$")
        self.assertEqual(first.finding_id, second.finding_id)
        self.assertEqual("2026-06-30T00:00:00Z", equivalent_timestamp.observed_at)
        self.assertEqual(first.finding_id, equivalent_timestamp.finding_id)
        self.assertNotEqual(first.finding_id, changed.finding_id)

    def test_sorting_uses_source_reference_before_hash_id(self):
        first = _finding(
            evidence_references=[
                EvidenceReference(type="test-record", id="record-1")
            ]
        )
        second = _finding(
            evidence_references=[
                EvidenceReference(type="test-record", id="record-2")
            ]
        )

        self.assertEqual([first, second], sort_findings([second, first]))
        self.assertEqual(
            ["record-1"],
            evidence_reference_ids(first, "test-record"),
        )

    def test_context_fills_unknown_values_without_overwriting_event_context(self):
        finding = _finding(
            account_id="unknown",
            region="unknown",
            observed_at=None,
        )
        enriched = with_finding_context(
            finding,
            account_id="999988887777",
            region="ap-southeast-2",
            observed_at="2026-07-01T00:00:00Z",
        )
        preserved = with_finding_context(
            enriched,
            account_id="111122223333",
            region="us-east-1",
            observed_at="2026-07-02T00:00:00Z",
        )

        self.assertEqual("999988887777", enriched.account_id)
        self.assertEqual("ap-southeast-2", enriched.region)
        self.assertEqual("2026-07-01T00:00:00Z", enriched.observed_at)
        self.assertNotEqual(finding.finding_id, enriched.finding_id)
        self.assertIs(enriched, preserved)

    def test_identity_field_changes_require_id_recalculation(self):
        finding = _finding()

        with self.assertRaisesRegex(ValueError, "stable identity"):
            replace(finding, region="us-east-1")

        changed = replace(finding, finding_id="", region="us-east-1")
        self.assertNotEqual(finding.finding_id, changed.finding_id)

    def test_provenance_values_are_strict(self):
        invalid_cases = (
            ({"confidence": "certain"}, "confidence"),
            ({"account_id": "123"}, "account_id"),
            ({"region": ""}, "region"),
            ({"observed_at": "2026-06-30"}, "observed_at"),
            ({"observed_at": "2026-06-30T00:00:00+0000"}, "RFC 3339"),
            (
                {
                    "evidence_references": [
                        EvidenceReference(type="test-record", id="same"),
                        EvidenceReference(type="test-record", id="same"),
                    ]
                },
                "duplicates",
            ),
        )
        for overrides, message in invalid_cases:
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(ValueError, message):
                    _finding(**overrides)

        with self.assertRaisesRegex(ValueError, "lowercase"):
            EvidenceReference(type="CloudTrail", id="event-1")

    def test_write_and_load_v2_round_trip(self):
        finding = _finding()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "findings.json"
            write_findings(path, [finding])
            payload = json.loads(path.read_text(encoding="utf-8"))
            loaded = load_findings_file(path)

        self.assertEqual("2.0", payload["schema_version"])
        self.assertEqual(finding, loaded[0])
        self.assertEqual(
            [{"type": "test-record", "id": "record-1"}],
            payload["findings"][0]["evidence_references"],
        )

    def test_v1_file_is_migrated_without_inventing_provenance(self):
        legacy_finding = {
            "rule_id": "TEST-001",
            "severity": "high",
            "module": "test",
            "category": "test",
            "resource_type": "resource",
            "resource_id": "example",
            "title": "Example finding",
            "evidence": "Synthetic evidence.",
            "impact": "Synthetic impact.",
            "remediation": "Synthetic remediation.",
            "references": [],
            "metadata": {},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "findings-v1.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "finding_count": 1,
                        "findings": [legacy_finding],
                    }
                ),
                encoding="utf-8",
            )
            migrated = load_findings_file(path)[0]

        self.assertEqual("unknown", migrated.account_id)
        self.assertEqual("unknown", migrated.region)
        self.assertIsNone(migrated.observed_at)
        self.assertEqual("unknown", migrated.confidence)
        self.assertEqual("legacy-finding", migrated.evidence_references[0].type)

    def test_v2_loader_rejects_tampered_id_and_missing_evidence_references(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "findings.json"
            write_findings(path, [_finding()])
            payload = json.loads(path.read_text(encoding="utf-8"))

            payload["findings"][0]["finding_id"] = "FND-" + ("0" * 32)
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "stable identity"):
                load_findings_file(path)

            payload["findings"][0]["evidence_references"] = []
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-empty"):
                load_findings_file(path)


if __name__ == "__main__":
    unittest.main()
