import copy
import json
import unittest
from pathlib import Path

from cloud_analysis import SkippedEvidence
from cloud_security_lab.analysis import build_analysis_summary

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _sample(relative_path: str):
    return json.loads((PROJECT_ROOT / relative_path).read_text(encoding="utf-8"))


class AnalysisCoverageBuilderTests(unittest.TestCase):
    def test_complete_summary_can_have_no_findings(self):
        summary = build_analysis_summary(
            module="storage",
            environment={
                "account_id": "111122223333",
                "buckets": [
                    {
                        "name": "private-bucket",
                        "object_ownership": "BucketOwnerEnforced",
                    }
                ],
            },
            input_format="simplified",
            input_file_count=1,
            finding_count=0,
        )

        self.assertEqual("complete", summary.coverage_status)
        self.assertEqual(1, summary.resource_coverage[0].evaluated_count)
        self.assertEqual(0, summary.finding_count)

    def test_empty_environment_is_distinct_from_complete_no_findings(self):
        summary = build_analysis_summary(
            module="storage",
            environment={"account_id": "111122223333", "buckets": []},
            input_format="simplified",
            input_file_count=1,
            finding_count=0,
        )

        self.assertEqual("empty", summary.coverage_status)
        self.assertEqual(0, summary.resource_coverage[0].evaluated_count)

    def test_missing_iam_evidence_makes_non_empty_analysis_partial(self):
        environment = _sample("sample_data/iam/sample_iam_environment.json")
        del environment["root_account"]
        del environment["users"][0]["password_last_used_days"]

        summary = build_analysis_summary(
            module="iam",
            environment=environment,
            input_format="simplified",
            input_file_count=1,
            finding_count=9,
        )

        self.assertEqual("partial", summary.coverage_status)
        self.assertEqual(
            {
                "IAM_PASSWORD_USAGE_ABSENT",
                "IAM_ROOT_CREDENTIAL_EVIDENCE_ABSENT",
            },
            {item.code for item in summary.skipped_evidence},
        )
        root_coverage = next(
            item
            for item in summary.resource_coverage
            if item.resource_type == "root-account"
        )
        self.assertEqual((1, 0, 1), (
            root_coverage.discovered_count,
            root_coverage.evaluated_count,
            root_coverage.skipped_count,
        ))

    def test_iam_summary_identifies_supported_credential_and_policy_gaps(self):
        environment = {
            "account_id": "111122223333",
            "users": [
                {
                    "name": "alice",
                    "groups": ["missing-group"],
                    "mfa_enabled": False,
                    "access_keys": [
                        {"id": "active-key", "status": "Active", "age_days": 10},
                        {"id": "inactive-key", "status": "Inactive", "age_days": 20},
                    ],
                    "attached_policies": [],
                    "permissions_boundary": {
                        "document_available": False,
                    },
                }
            ],
            "roles": [],
        }

        summary = build_analysis_summary(
            module="iam",
            environment=environment,
            input_format="simplified",
            input_file_count=1,
            finding_count=1,
            skipped_evidence=[
                SkippedEvidence(
                    code="IAM_IDENTITY_DETAIL_ABSENT",
                    evidence_type="iam-identity-detail",
                    reason=(
                        "Credential-report identities absent from authorization details "
                        "could not be evaluated for permissions."
                    ),
                    count=1,
                    affects_coverage=True,
                    resource_ids=["credential-only-user"],
                )
            ],
        )

        self.assertEqual(
            {
                "IAM_ACCESS_KEY_USAGE_ABSENT",
                "IAM_CONSOLE_PASSWORD_STATUS_ABSENT",
                "IAM_GROUP_DETAIL_ABSENT",
                "IAM_GROUP_INVENTORY_ABSENT",
                "IAM_IDENTITY_DETAIL_ABSENT",
                "IAM_PERMISSIONS_BOUNDARY_DOCUMENT_ABSENT",
                "IAM_ROOT_CREDENTIAL_EVIDENCE_ABSENT",
            },
            {item.code for item in summary.skipped_evidence},
        )
        group_coverage = summary.resource_coverage[0]
        self.assertEqual((1, 0, 1), (
            group_coverage.discovered_count,
            group_coverage.evaluated_count,
            group_coverage.skipped_count,
        ))
        user_coverage = next(
            item
            for item in summary.resource_coverage
            if item.resource_type == "user"
        )
        self.assertEqual((2, 1, 1), (
            user_coverage.discovered_count,
            user_coverage.evaluated_count,
            user_coverage.skipped_count,
        ))

    def test_network_summary_exposes_unresolved_peers_and_missing_context(self):
        environment = {
            "account_id": "111122223333",
            "security_groups": [
                {
                    "id": "sg-example",
                    "name": "example",
                    "inbound_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 443,
                            "to_port": 443,
                            "peer_type": "security_group",
                            "peer_id": "sg-peer",
                        }
                    ],
                    "outbound_rules": [],
                }
            ],
        }

        summary = build_analysis_summary(
            module="network",
            environment=environment,
            input_format="aws",
            input_file_count=1,
            finding_count=0,
        )

        self.assertEqual("partial", summary.coverage_status)
        self.assertEqual(
            {
                "NET_REACHABILITY_NOT_ASSESSED",
                "NET_SECURITY_GROUP_TARGET_UNRESOLVED",
            },
            {item.code for item in summary.skipped_evidence},
        )

    def test_storage_summary_marks_missing_object_ownership(self):
        summary = build_analysis_summary(
            module="storage",
            environment={
                "account_id": "111122223333",
                "buckets": [{"name": "legacy-bucket"}],
            },
            input_format="simplified",
            input_file_count=1,
            finding_count=0,
        )

        self.assertEqual("partial", summary.coverage_status)
        self.assertEqual(
            "STO_OBJECT_OWNERSHIP_ABSENT",
            summary.skipped_evidence[0].code,
        )

    def test_identical_cloudtrail_duplicate_is_skipped_without_coverage_loss(self):
        environment = _sample(
            "sample_data/cloudtrail/sample_cloudtrail_events.json"
        )
        environment["events"].append(copy.deepcopy(environment["events"][0]))

        summary = build_analysis_summary(
            module="cloudtrail",
            environment=environment,
            input_format="simplified",
            input_file_count=1,
            finding_count=11,
            incident_count=2,
        )
        coverage = summary.resource_coverage[0]

        self.assertEqual("complete", summary.coverage_status)
        self.assertEqual(18, coverage.discovered_count)
        self.assertEqual(17, coverage.evaluated_count)
        self.assertEqual(1, coverage.skipped_count)
        self.assertFalse(summary.skipped_evidence[0].affects_coverage)

    def test_conflicting_simplified_event_ids_stop_summary_in_any_order(self):
        event = {
            "eventID": "event-1",
            "eventTime": "2026-06-30T01:00:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "sourceIPAddress": "192.0.2.1",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
        }
        conflicting = copy.deepcopy(event)
        conflicting["eventName"] = "StopInstances"

        for label, events in (
            ("original-first", [event, conflicting]),
            ("conflicting-first", [conflicting, event]),
        ):
            with self.subTest(order=label), self.assertRaisesRegex(
                ValueError,
                "Conflicting CloudTrail events share eventID 'event-1'",
            ):
                build_analysis_summary(
                    module="cloudtrail",
                    environment={
                        "account_id": "111122223333",
                        "events": events,
                    },
                    input_format="simplified",
                    input_file_count=1,
                    finding_count=0,
                )

    def test_cloudtrail_summary_exposes_invalid_and_incomplete_events(self):
        summary = build_analysis_summary(
            module="cloudtrail",
            environment={
                "account_id": "111122223333",
                "events": [
                    "not-an-event",
                    {
                        "eventTime": "2026-06-30T01:00:00Z",
                        "eventName": "ConsoleLogin",
                        "sourceIPAddress": "192.0.2.1",
                        "userIdentity": {
                            "type": "IAMUser",
                            "userName": "alice",
                        },
                    },
                ],
            },
            input_format="simplified",
            input_file_count=1,
            finding_count=0,
        )

        self.assertEqual("partial", summary.coverage_status)
        self.assertEqual(
            {
                "CLD_CONSOLE_LOGIN_MFA_EVIDENCE_ABSENT",
                "CLD_EVENT_ID_ABSENT",
                "CLD_EVENT_NOT_OBJECT",
            },
            {item.code for item in summary.skipped_evidence},
        )
        self.assertEqual(2, summary.resource_coverage[0].discovered_count)

    def test_external_skipped_evidence_is_merged_deterministically(self):
        skipped = SkippedEvidence(
            code="CLD_DUPLICATE_EVENT",
            evidence_type="cloudtrail-event",
            reason="Identical records sharing an event ID were analyzed once.",
            count=2,
            affects_coverage=False,
            resource_ids=["event-1"],
        )
        summary = build_analysis_summary(
            module="cloudtrail",
            environment={
                "account_id": "111122223333",
                "events": [
                    {
                        "eventID": "event-1",
                        "eventTime": "2026-06-30T01:00:00Z",
                        "eventName": "DescribeInstances",
                        "sourceIPAddress": "192.0.2.1",
                        "userIdentity": {"type": "IAMUser"},
                    }
                ],
            },
            input_format="aws",
            input_file_count=2,
            finding_count=0,
            skipped_evidence=[skipped],
            warnings=["Two duplicates were removed.", "Two duplicates were removed."],
        )

        self.assertEqual("complete", summary.coverage_status)
        self.assertEqual(3, summary.resource_coverage[0].discovered_count)
        self.assertEqual(["Two duplicates were removed."], summary.warnings)

    def test_invalid_module_and_resource_containers_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported analyzer module"):
            build_analysis_summary(
                module="compute",
                environment={},
                input_format="simplified",
                input_file_count=1,
                finding_count=0,
            )

        for module, key in (
            ("iam", "users"),
            ("storage", "buckets"),
            ("network", "security_groups"),
            ("cloudtrail", "events"),
        ):
            with self.subTest(module=module), self.assertRaisesRegex(
                ValueError, "expected"
            ):
                build_analysis_summary(
                    module=module,
                    environment={key: {}},
                    input_format="simplified",
                    input_file_count=1,
                    finding_count=0,
                )


if __name__ == "__main__":
    unittest.main()
