import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from cloud_findings import EvidenceReference, Finding
from cloud_incidents import Incident
from cloud_remediation import (
    RemediationAction,
    RemediationPlan,
    build_remediation_plan,
    load_remediation_plan_file,
    remediation_plan_from_dict,
    remediation_plan_to_dict,
    write_remediation_plan,
)


def _finding(**overrides):
    values = {
        "rule_id": "CLD-002",
        "severity": "high",
        "module": "cloudtrail",
        "category": "audit-and-detection",
        "resource_type": "identity",
        "resource_id": "alice",
        "title": "MFA device was disabled or deleted",
        "evidence": "MFA was disabled.",
        "impact": "Identity protection was weakened.",
        "remediation": "Restore MFA and validate the change.",
        "metadata": {"event_id": "event-1"},
    }
    values.update(overrides)
    return Finding(**values)


def _incident(**overrides):
    values = {
        "incident_id": "CTI-ABCDEF123456",
        "severity": "critical",
        "confidence": "high",
        "module": "cloudtrail",
        "category": "correlated-activity",
        "title": "Identity protection weakened",
        "actor": "alice",
        "source_ip": "192.0.2.1",
        "first_seen": "2026-06-30T01:00:00Z",
        "last_seen": "2026-06-30T01:05:00Z",
        "event_count": 2,
        "finding_count": 1,
        "rule_ids": ["CLD-002"],
        "event_ids": ["event-1", "event-2"],
        "resources": ["identity/alice"],
        "summary": "MFA was disabled during suspicious activity.",
        "recommended_actions": ["Contain the identity.", "Restore MFA."],
        "references": ["https://example.com/reference"],
    }
    values.update(overrides)
    return Incident(**values)


class RemediationPlanTests(unittest.TestCase):
    def test_priorities_separate_response_from_configuration(self):
        linked_finding = _finding()
        critical_configuration = _finding(
            rule_id="IAM-001",
            severity="critical",
            module="iam",
            resource_type="user",
            title="Administrator-style wildcard permission",
            remediation="Replace wildcard administration with least privilege.",
        )
        high_configuration = _finding(
            rule_id="IAM-004",
            module="iam",
            resource_type="user",
            title="Broad S3 write permission",
            remediation="Scope S3 write access.",
        )
        medium_configuration = _finding(
            rule_id="IAM-003",
            severity="medium",
            module="iam",
            resource_type="role",
            resource_id="audit",
            title="Wildcard resource scope",
            remediation="Scope resources.",
        )

        plan = build_remediation_plan(
            [
                medium_configuration,
                high_configuration,
                critical_configuration,
                linked_finding,
            ],
            [_incident()],
        )

        priorities = {
            (action.work_type, action.rule_ids[0]): action.priority
            for action in plan.actions
        }
        self.assertEqual("P0", priorities[("incident-response", "CLD-002")])
        self.assertEqual("P1", priorities[("configuration", "CLD-002")])
        self.assertEqual("P1", priorities[("configuration", "IAM-001")])
        self.assertEqual("P2", priorities[("configuration", "IAM-004")])
        self.assertEqual("P3", priorities[("configuration", "IAM-003")])

    def test_non_p0_incident_is_p1_and_linked_configuration_is_p2(self):
        incident = _incident(
            severity="medium",
            confidence="medium",
        )

        plan = build_remediation_plan([_finding(severity="medium")], [incident])

        self.assertEqual(
            ["P1", "P2"],
            [action.priority for action in plan.actions],
        )

    def test_same_rule_and_resource_without_shared_event_is_not_linked(self):
        unrelated = _finding(
            severity="medium",
            metadata={"event_id": "event-unrelated"},
        )

        plan = build_remediation_plan([unrelated], [_incident()])

        configuration = next(
            action
            for action in plan.actions
            if action.work_type == "configuration"
        )
        self.assertEqual([], configuration.incident_ids)
        self.assertEqual("P3", configuration.priority)

    def test_incident_link_uses_v2_evidence_reference(self):
        finding = _finding(
            metadata={},
            evidence_references=[
                EvidenceReference(type="cloudtrail-event", id="event-1")
            ],
        )

        plan = build_remediation_plan([finding], [_incident()])

        configuration = next(
            action
            for action in plan.actions
            if action.work_type == "configuration"
        )
        self.assertEqual(["CTI-ABCDEF123456"], configuration.incident_ids)

    def test_equivalent_findings_are_grouped_without_losing_scope(self):
        first = _finding(
            rule_id="STO-005",
            severity="medium",
            module="storage",
            resource_type="bucket",
            resource_id="bucket-b",
            title="Bucket versioning is not enabled",
            remediation="Enable versioning.",
        )
        second = replace(first, finding_id="", resource_id="bucket-a")

        plan = build_remediation_plan([first, second], [])

        self.assertEqual(1, len(plan.actions))
        action = plan.actions[0]
        self.assertEqual(2, action.finding_count)
        self.assertEqual(
            ["bucket/bucket-a", "bucket/bucket-b"],
            action.resources,
        )
        self.assertIn("2 medium findings", action.rationale)

    def test_custom_rule_confidence_is_not_inferred(self):
        finding = _finding(
            rule_id="CUSTOM-001",
            severity="info",
            module="custom",
            title="Custom extension",
            remediation="Review the extension result.",
        )

        plan = build_remediation_plan([finding], [])

        self.assertEqual("not-assessed", plan.actions[0].confidence)
        self.assertEqual("P3", plan.actions[0].priority)

    def test_configuration_action_prefers_finding_confidence(self):
        finding = _finding(confidence="low")

        plan = build_remediation_plan([finding], [])

        self.assertEqual("low", plan.actions[0].confidence)

    def test_input_order_does_not_change_actions_or_ids(self):
        findings = [
            _finding(),
            _finding(
                rule_id="IAM-003",
                severity="medium",
                module="iam",
                resource_type="role",
                resource_id="audit",
                title="Wildcard resource scope",
                remediation="Scope resources.",
            ),
        ]

        first = build_remediation_plan(findings, [_incident()])
        second = build_remediation_plan(list(reversed(findings)), [_incident()])

        self.assertEqual(first, second)

    def test_round_trip_uses_versioned_contract(self):
        plan = build_remediation_plan([_finding()], [_incident()])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "remediation.json"
            write_remediation_plan(path, plan)
            payload = json.loads(path.read_text(encoding="utf-8"))
            loaded = load_remediation_plan_file(path)

        self.assertEqual("1.0", payload["schema_version"])
        self.assertEqual(2, payload["action_count"])
        self.assertEqual(remediation_plan_to_dict(plan), payload)
        self.assertEqual(plan, loaded)

    def test_plan_rejects_incomplete_finding_or_incident_accounting(self):
        plan = build_remediation_plan([_finding()], [_incident()])

        with self.assertRaisesRegex(ValueError, "every source finding"):
            RemediationPlan(
                schema_version=plan.schema_version,
                source_finding_count=2,
                source_incident_count=plan.source_incident_count,
                actions=plan.actions,
            )
        with self.assertRaisesRegex(ValueError, "every source incident"):
            RemediationPlan(
                schema_version=plan.schema_version,
                source_finding_count=plan.source_finding_count,
                source_incident_count=2,
                actions=plan.actions,
            )

    def test_action_contract_rejects_invalid_fields_and_ordering(self):
        action = build_remediation_plan([_finding()], [_incident()]).actions[0]
        cases = (
            ({"action_id": "bad-id"}, "action_id"),
            ({"priority": "P9"}, "priority"),
            ({"work_type": "ticket"}, "work_type"),
            ({"severity": "urgent"}, "severity"),
            ({"confidence": "certain"}, "confidence"),
            ({"module": ""}, "module"),
            ({"finding_count": 0}, "finding_count"),
            ({"rule_ids": []}, "rule_ids"),
            (
                {"resources": ["identity/z", "identity/a"]},
                "sorted order",
            ),
            ({"incident_ids": ["incident-1"]}, "invalid ID"),
            (
                {"actions": ["Contain the identity.", "Contain the identity."]},
                "duplicates",
            ),
            ({"incident_ids": []}, "exactly one incident"),
        )
        for changes, message in cases:
            with self.subTest(changes=changes), self.assertRaisesRegex(
                ValueError, message
            ):
                RemediationAction(
                    **{
                        **action.__dict__,
                        **changes,
                    }
                )

    def test_plan_rejects_bad_version_counts_and_action_order(self):
        plan = build_remediation_plan([_finding()], [_incident()])
        cases = (
            (
                {
                    "schema_version": "999.0",
                    "source_finding_count": plan.source_finding_count,
                    "source_incident_count": plan.source_incident_count,
                    "actions": plan.actions,
                },
                "schema version",
            ),
            (
                {
                    "schema_version": plan.schema_version,
                    "source_finding_count": True,
                    "source_incident_count": plan.source_incident_count,
                    "actions": plan.actions,
                },
                "source_finding_count",
            ),
            (
                {
                    "schema_version": plan.schema_version,
                    "source_finding_count": plan.source_finding_count,
                    "source_incident_count": plan.source_incident_count,
                    "actions": tuple(reversed(plan.actions)),
                },
                "priority order",
            ),
        )
        for values, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                ValueError, message
            ):
                RemediationPlan(**values)

    def test_deserializer_rejects_missing_unexpected_and_malformed_fields(self):
        payload = remediation_plan_to_dict(
            build_remediation_plan([_finding()], [_incident()])
        )

        missing = dict(payload)
        del missing["schema_version"]
        with self.assertRaisesRegex(ValueError, "missing fields"):
            remediation_plan_from_dict(missing)

        unexpected = dict(payload)
        unexpected["owner"] = "security-team"
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            remediation_plan_from_dict(unexpected)

        malformed_actions = dict(payload)
        malformed_actions["actions"] = "not-a-list"
        with self.assertRaisesRegex(ValueError, "JSON list"):
            remediation_plan_from_dict(malformed_actions)

        malformed_count = dict(payload)
        malformed_count["action_count"] = True
        with self.assertRaisesRegex(ValueError, "integer"):
            remediation_plan_from_dict(malformed_count)

        malformed_action = json.loads(json.dumps(payload))
        malformed_action["actions"][0]["owner"] = "security-team"
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            remediation_plan_from_dict(malformed_action)

    def test_loader_rejects_bad_count_and_unversioned_payload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "remediation.json"
            path.write_text("[]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "versioned"):
                load_remediation_plan_file(path)

            path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "source_finding_count": 0,
                        "source_incident_count": 0,
                        "action_count": 1,
                        "actions": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "action_count"):
                load_remediation_plan_file(path)


if __name__ == "__main__":
    unittest.main()
