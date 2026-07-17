import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from cloud_findings import EvidenceReference, Finding
from cloud_incidents import Incident
from cloud_rules import load_builtin_catalog
from cloud_timeline import (
    RULE_ACTIVITY_TYPES,
    TimelineOmission,
    activity_label,
    attack_timeline_from_dict,
    attack_timeline_to_dict,
    build_attack_timeline,
    build_incident_narrative,
    load_attack_timeline_file,
    write_attack_timeline,
)
from cloudtrail_detector.detector import analyze_activity

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _sample_result():
    environment = json.loads(
        (
            PROJECT_ROOT
            / "sample_data/cloudtrail/sample_cloudtrail_events.json"
        ).read_text(encoding="utf-8")
    )
    return analyze_activity(environment)


def _finding(
    *,
    rule_id: str = "CLD-002",
    event_time: str | None = "2026-06-30T01:04:00Z",
    event_id: str | None = "event-1",
) -> Finding:
    metadata = {
        "actor": "alice",
        "source_ip": "192.0.2.1",
        "event_name": "DeactivateMFADevice",
    }
    if event_time is not None:
        metadata["event_time"] = event_time
    if event_id is not None:
        metadata["event_id"] = event_id
    return Finding(
        rule_id=rule_id,
        severity="high",
        module="cloudtrail",
        category="cloud-audit",
        resource_type="identity",
        resource_id="alice",
        title="Identity protection changed",
        evidence="An identity protection setting changed.",
        impact="Account protection may be weaker.",
        remediation="Validate and restore the setting.",
        metadata=metadata,
    )


def _incident(*, event_ids: list[str] | None = None) -> Incident:
    return Incident(
        incident_id="CTI-ABCDEF123456",
        severity="high",
        confidence="high",
        module="cloudtrail",
        category="correlated-activity",
        title="Related control-plane activity",
        actor="alice",
        source_ip="192.0.2.1",
        first_seen="2026-06-30T01:04:00Z",
        last_seen="2026-06-30T01:05:00Z",
        event_count=len(event_ids or ["event-1"]),
        finding_count=1,
        rule_ids=["CLD-002"],
        event_ids=event_ids or ["event-1"],
        resources=["identity/alice"],
        summary="Related activity was observed.",
        recommended_actions=["Validate the activity."],
        references=["https://example.com/reference"],
    )


class AttackTimelineTests(unittest.TestCase):
    def test_sample_timeline_is_complete_chronological_and_linked(self):
        result = _sample_result()

        timeline = build_attack_timeline(result.findings, result.incidents)

        self.assertEqual(11, timeline.source_cloudtrail_finding_count)
        self.assertEqual(2, timeline.source_incident_count)
        self.assertEqual(11, len(timeline.entries))
        self.assertEqual((), timeline.omissions)
        self.assertEqual(
            [
                "CLD-001",
                "CLD-002",
                "CLD-003",
                "CLD-004",
                "CLD-005",
                "CLD-008",
                "CLD-009",
                "CLD-010",
                "CLD-011",
                "CLD-007",
                "CLD-006",
            ],
            [entry.rule_id for entry in timeline.entries],
        )
        linked_counts = sorted(
            sum(
                incident.incident_id in entry.incident_ids
                for entry in timeline.entries
            )
            for incident in result.incidents
        )
        self.assertEqual([1, 8], linked_counts)
        self.assertFalse(
            next(
                entry for entry in timeline.entries if entry.rule_id == "CLD-001"
            ).incident_ids
        )
        self.assertFalse(
            next(
                entry for entry in timeline.entries if entry.rule_id == "CLD-007"
            ).incident_ids
        )

    def test_failure_spike_preserves_time_range_and_all_event_ids(self):
        result = _sample_result()
        timeline = build_attack_timeline(result.findings, result.incidents)

        entry = next(
            item for item in timeline.entries if item.rule_id == "CLD-006"
        )

        self.assertEqual("2026-06-30T02:00:00Z", entry.first_seen)
        self.assertEqual("2026-06-30T02:08:00Z", entry.last_seen)
        self.assertEqual(6, len(entry.event_ids))
        self.assertEqual("discovery-and-probing", entry.activity_type)
        self.assertEqual(1, len(entry.incident_ids))

    def test_timeline_prefers_finding_confidence(self):
        finding = replace(_finding(), confidence="low")

        timeline = build_attack_timeline([finding], [])

        self.assertEqual("low", timeline.entries[0].confidence)

    def test_timeline_uses_v2_provenance_without_legacy_metadata(self):
        finding = _finding(
            event_time="2026-06-30T05:04:00Z",
            event_id="legacy-event",
        )
        finding = replace(
            finding,
            finding_id="",
            observed_at="2026-06-30T01:04:00Z",
            evidence_references=[
                EvidenceReference(type="cloudtrail-event", id="event-v2")
            ],
        )

        timeline = build_attack_timeline([finding], [])

        self.assertEqual(1, len(timeline.entries))
        self.assertEqual(
            "2026-06-30T01:04:00Z",
            timeline.entries[0].first_seen,
        )
        self.assertEqual(
            ["event-v2"],
            timeline.entries[0].event_ids,
        )

    def test_missing_or_invalid_chronology_becomes_explicit_omission(self):
        reversed_range = _finding()
        reversed_range = replace(
            reversed_range,
            metadata={
                **reversed_range.metadata,
                "first_seen": "2026-06-30T01:05:00Z",
                "last_seen": "2026-06-30T01:04:00Z",
            },
        )
        findings = [
            _finding(event_time=None),
            _finding(event_time="not-a-time"),
            reversed_range,
            _finding(event_id=None),
        ]

        timeline = build_attack_timeline(findings, [])

        self.assertEqual(0, len(timeline.entries))
        self.assertEqual(
            {
                "missing-timestamp",
                "invalid-timestamp",
                "invalid-time-range",
                "missing-event-id",
            },
            {item.reason for item in timeline.omissions},
        )

    def test_unknown_cloudtrail_rule_uses_conservative_classification(self):
        timeline = build_attack_timeline(
            [_finding(rule_id="CUSTOM-CLOUD-001")],
            [],
        )

        entry = timeline.entries[0]
        self.assertEqual("other-observed-activity", entry.activity_type)
        self.assertEqual("not-assessed", entry.confidence)

    def test_incident_link_requires_matching_rule_resource_and_event(self):
        finding = _finding(event_id="finding-event")

        timeline = build_attack_timeline(
            [finding],
            [_incident(event_ids=["different-event"])],
        )

        self.assertEqual([], timeline.entries[0].incident_ids)

    def test_input_order_does_not_change_timeline_or_entry_ids(self):
        result = _sample_result()

        forward = build_attack_timeline(result.findings, result.incidents)
        reversed_input = build_attack_timeline(
            reversed(result.findings),
            reversed(result.incidents),
        )

        self.assertEqual(
            attack_timeline_to_dict(forward),
            attack_timeline_to_dict(reversed_input),
        )

    def test_incident_narrative_adds_context_without_claiming_causation(self):
        result = _sample_result()
        timeline = build_attack_timeline(result.findings, result.incidents)
        multi_signal = next(
            incident
            for incident in result.incidents
            if len(incident.rule_ids) > 1
        )

        narrative = build_incident_narrative(multi_signal, timeline)

        self.assertIn("8 linked timeline entries", narrative.observed_sequence)
        self.assertIn("19 minutes", narrative.observed_sequence)
        self.assertIn("Monitoring impairment", narrative.observed_sequence)
        self.assertIn("telemetry continuity", narrative.analyst_context)
        self.assertIn("recovery dependencies", narrative.analyst_context)
        self.assertIn("durable access paths", narrative.analyst_context)
        self.assertIn(
            "not malicious intent or proof",
            narrative.analyst_context,
        )

    def test_failure_incident_narrative_preserves_plausible_alternatives(self):
        result = _sample_result()
        timeline = build_attack_timeline(result.findings, result.incidents)
        failure_incident = next(
            incident
            for incident in result.incidents
            if incident.rule_ids == ["CLD-006"]
        )

        narrative = build_incident_narrative(failure_incident, timeline)

        self.assertIn("1 linked timeline entry represents", narrative.observed_sequence)
        self.assertIn("automation errors", narrative.analyst_context)
        self.assertIn("permission drift", narrative.analyst_context)

    def test_unlinked_incident_has_an_explicit_evidence_gap(self):
        timeline = build_attack_timeline([], [_incident()])

        narrative = build_incident_narrative(_incident(), timeline)

        self.assertIn(
            "No timeline entry could be linked",
            narrative.observed_sequence,
        )
        self.assertIn(
            "cannot add finding-level chronology",
            narrative.analyst_context,
        )

    def test_json_round_trip_and_strict_validation(self):
        result = _sample_result()
        timeline = build_attack_timeline(result.findings, result.incidents)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "timeline.json"
            write_attack_timeline(path, timeline)
            loaded = load_attack_timeline_file(path)

        self.assertEqual(timeline, loaded)
        payload = attack_timeline_to_dict(timeline)
        payload["entry_count"] += 1
        with self.assertRaisesRegex(ValueError, "entry_count"):
            attack_timeline_from_dict(payload)

        payload = attack_timeline_to_dict(timeline)
        payload["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            attack_timeline_from_dict(payload)

    def test_timeline_entry_rejects_invalid_fields_and_ordering(self):
        entry = build_attack_timeline([_finding()], []).entries[0]
        invalid_cases = (
            ({"entry_id": "invalid"}, "entry_id"),
            ({"first_seen": "2026-06-30T01:04:00"}, "UTC"),
            ({"last_seen": "2026-06-30T01:03:00Z"}, "precede"),
            ({"severity": "urgent"}, "severity"),
            ({"confidence": "certain"}, "confidence"),
            ({"activity_type": "attack-phase"}, "activity_type"),
            ({"title": ""}, "non-empty"),
            ({"event_names": ("ConsoleLogin",)}, "must be a list"),
            ({"event_ids": []}, "non-empty list"),
            ({"event_ids": [""]}, "non-empty strings"),
            ({"event_ids": ["event-1", "event-1"]}, "duplicates"),
            ({"event_ids": ["event-2", "event-1"]}, "sorted order"),
            ({"incident_ids": ["invalid"]}, "invalid ID"),
        )

        for changes, message in invalid_cases:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, message):
                    replace(entry, **changes)

        with self.assertRaisesRegex(ValueError, "Unknown timeline activity"):
            activity_label("attack-phase")

    def test_attack_timeline_rejects_inconsistent_model_state(self):
        result = _sample_result()
        timeline = build_attack_timeline(result.findings, result.incidents)
        first_entry, second_entry = timeline.entries[:2]
        omission_a = TimelineOmission("CLD-001", "identity/root", "missing-event-id")
        omission_b = TimelineOmission("CLD-002", "identity/alice", "missing-event-id")
        invalid_cases = (
            ({"schema_version": "2.0"}, "Unsupported"),
            ({"source_incident_count": True}, "non-negative integer"),
            ({"source_incident_count": -1}, "non-negative integer"),
            ({"entries": list(timeline.entries)}, "entries must be a tuple"),
            ({"omissions": []}, "omissions must be a tuple"),
            (
                {
                    "source_cloudtrail_finding_count": 2,
                    "source_incident_count": 0,
                    "entries": (second_entry, first_entry),
                    "omissions": (),
                },
                "chronological order",
            ),
            (
                {
                    "source_cloudtrail_finding_count": 2,
                    "source_incident_count": 0,
                    "entries": (first_entry, first_entry),
                    "omissions": (),
                },
                "IDs must be unique",
            ),
            (
                {
                    "source_cloudtrail_finding_count": 2,
                    "source_incident_count": 0,
                    "entries": (),
                    "omissions": (omission_b, omission_a),
                },
                "omissions must use deterministic",
            ),
            (
                {
                    "source_cloudtrail_finding_count": 2,
                    "source_incident_count": 0,
                    "entries": (),
                    "omissions": (omission_a, omission_a),
                },
                "omissions must be unique",
            ),
            ({"source_cloudtrail_finding_count": 12}, "account for every"),
        )

        for changes, message in invalid_cases:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, message):
                    replace(timeline, **changes)

        with self.assertRaisesRegex(ValueError, "non-empty"):
            TimelineOmission("", "identity/root", "missing-event-id")
        with self.assertRaisesRegex(ValueError, "reason is invalid"):
            TimelineOmission("CLD-001", "identity/root", "unknown")

    def test_strict_deserializer_rejects_malformed_shapes(self):
        timeline = build_attack_timeline([_finding()], [])
        base_payload = attack_timeline_to_dict(timeline)
        malformed_cases = []

        missing_top_level = dict(base_payload)
        del missing_top_level["schema_version"]
        malformed_cases.append((missing_top_level, "missing fields"))

        entries_not_list = dict(base_payload)
        entries_not_list["entries"] = {}
        malformed_cases.append((entries_not_list, "entries must be a JSON list"))

        omissions_not_list = dict(base_payload)
        omissions_not_list["omissions"] = {}
        malformed_cases.append(
            (omissions_not_list, "omissions must be a JSON list")
        )

        bool_count = dict(base_payload)
        bool_count["entry_count"] = True
        malformed_cases.append((bool_count, "entry_count must be an integer"))

        entry_not_object = dict(base_payload)
        entry_not_object["entries"] = ["invalid"]
        malformed_cases.append((entry_not_object, "entry must be a JSON object"))

        missing_entry_field = json.loads(json.dumps(base_payload))
        del missing_entry_field["entries"][0]["title"]
        malformed_cases.append((missing_entry_field, "entry is missing fields"))

        unexpected_entry_field = json.loads(json.dumps(base_payload))
        unexpected_entry_field["entries"][0]["unexpected"] = True
        malformed_cases.append(
            (unexpected_entry_field, "entry contains unsupported fields")
        )

        omission_payload = attack_timeline_to_dict(
            build_attack_timeline([_finding(event_id=None)], [])
        )
        omission_not_object = dict(omission_payload)
        omission_not_object["omissions"] = ["invalid"]
        malformed_cases.append(
            (omission_not_object, "omission must be a JSON object")
        )

        missing_omission_field = json.loads(json.dumps(omission_payload))
        del missing_omission_field["omissions"][0]["reason"]
        malformed_cases.append(
            (missing_omission_field, "omission is missing fields")
        )

        unexpected_omission_field = json.loads(json.dumps(omission_payload))
        unexpected_omission_field["omissions"][0]["unexpected"] = True
        malformed_cases.append(
            (
                unexpected_omission_field,
                "omission contains unsupported fields",
            )
        )

        with self.assertRaisesRegex(ValueError, "versioned JSON object"):
            attack_timeline_from_dict([])
        for payload, message in malformed_cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    attack_timeline_from_dict(payload)

    def test_activity_mapping_covers_every_builtin_cloudtrail_rule(self):
        cloudtrail_rule_ids = {
            rule.rule_id
            for rule in load_builtin_catalog().rules
            if rule.module == "cloudtrail"
        }

        self.assertEqual(cloudtrail_rule_ids, set(RULE_ACTIVITY_TYPES))


if __name__ == "__main__":
    unittest.main()
