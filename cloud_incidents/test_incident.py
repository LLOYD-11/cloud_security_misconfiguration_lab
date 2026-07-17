import json
import tempfile
import unittest
from pathlib import Path

from cloud_incidents import (
    Incident,
    incidents_to_dicts,
    load_incidents_file,
    write_incidents,
)


def _incident(**overrides):
    values = {
        "incident_id": "CTI-ABCDEF123456",
        "severity": "high",
        "confidence": "medium",
        "module": "cloudtrail",
        "category": "correlated-activity",
        "title": "Correlated activity",
        "actor": "alice",
        "source_ip": "192.0.2.1",
        "first_seen": "2026-06-30T01:00:00Z",
        "last_seen": "2026-06-30T01:05:00Z",
        "event_count": 2,
        "finding_count": 2,
        "rule_ids": ["CLD-002", "CLD-005"],
        "event_ids": ["event-1", "event-2"],
        "resources": ["identity/alice", "iam_policy/example"],
        "summary": "Two related signals were observed.",
        "recommended_actions": ["Validate the activity."],
        "references": ["https://example.com/reference"],
    }
    values.update(overrides)
    return Incident(**values)


class IncidentModelTests(unittest.TestCase):
    def test_round_trip_uses_versioned_contract(self):
        incident = _incident()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "incidents.json"
            write_incidents(path, [incident])
            payload = json.loads(path.read_text(encoding="utf-8"))
            loaded = load_incidents_file(path)

        self.assertEqual("1.0", payload["schema_version"])
        self.assertEqual(1, payload["incident_count"])
        self.assertEqual(incidents_to_dicts([incident]), payload["incidents"])
        self.assertEqual([incident], loaded)

    def test_invalid_severity_confidence_and_times_are_rejected(self):
        cases = (
            ({"incident_id": "incident-1"}, "incident_id"),
            ({"severity": "urgent"}, "severity"),
            ({"confidence": "certain"}, "confidence"),
            ({"first_seen": "not-a-time"}, "first_seen"),
            ({"first_seen": "2026-06-30T01:00:00"}, "must use UTC"),
            (
                {
                    "first_seen": "2026-06-30T02:00:00Z",
                    "last_seen": "2026-06-30T01:00:00Z",
                },
                "must not precede",
            ),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides), self.assertRaisesRegex(
                ValueError, message
            ):
                _incident(**overrides)

    def test_counts_and_evidence_lists_are_validated(self):
        cases = (
            ({"event_count": 0}, "event_count"),
            ({"finding_count": True}, "finding_count"),
            ({"rule_ids": []}, "rule_ids"),
            ({"event_ids": ["event-1", "event-1"]}, "duplicates"),
            ({"event_count": 3}, "must equal"),
            ({"finding_count": 1}, "distinct rule count"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides), self.assertRaisesRegex(
                ValueError, message
            ):
                _incident(**overrides)

    def test_loader_rejects_bad_version_count_and_missing_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "incidents.json"
            path.write_text(
                '{"schema_version":"999.0","incident_count":0,"incidents":[]}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "schema version"):
                load_incidents_file(path)

            path.write_text(
                '{"schema_version":"1.0","incident_count":1,"incidents":[]}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "incident_count"):
                load_incidents_file(path)

            payload = {
                "schema_version": "1.0",
                "incident_count": 1,
                "incidents": [{}],
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing required fields"):
                load_incidents_file(path)

            incident_payload = json.loads(json.dumps(_incident(), default=lambda item: item.__dict__))
            incident_payload["unexpected"] = "value"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "incident_count": 1,
                        "incidents": [incident_payload],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unsupported fields"):
                load_incidents_file(path)


if __name__ == "__main__":
    unittest.main()
