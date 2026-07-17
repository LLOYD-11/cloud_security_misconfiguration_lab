import copy
import json
import tempfile
import unittest
from pathlib import Path

from cloud_security_lab.normalizers.ec2 import load_aws_ec2_environment
from cloud_security_lab.normalizers.network_context import (
    apply_network_reachability_context,
    load_network_reachability_context,
    normalize_network_reachability_context,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONTEXT_PATH = (
    PROJECT_ROOT / "sample_data/aws/ec2/network_reachability_context.json"
)
EC2_PATH = PROJECT_ROOT / "sample_data/aws/ec2/describe_security_groups.json"


def _payload():
    return json.loads(CONTEXT_PATH.read_text(encoding="utf-8"))


class NetworkReachabilityContextTests(unittest.TestCase):
    def test_sample_context_enriches_environment_without_mutating_source(self):
        environment = load_aws_ec2_environment(EC2_PATH).environment
        original = copy.deepcopy(environment)
        assessments = load_network_reachability_context(CONTEXT_PATH)

        result = apply_network_reachability_context(environment, assessments)

        self.assertEqual(original, environment)
        self.assertEqual((), result.warnings)
        self.assertEqual(
            "reachable",
            result.environment["security_groups"][0]["reachability"]["ingress"]["status"],
        )
        self.assertEqual(
            "not_reachable",
            result.environment["security_groups"][1]["reachability"]["ingress"]["status"],
        )

    def test_partial_context_warns_and_leaves_unmatched_groups_unmodified(self):
        environment = load_aws_ec2_environment(EC2_PATH).environment
        assessments = load_network_reachability_context(CONTEXT_PATH)
        first_group_id = environment["security_groups"][0]["id"]
        second_group_id = environment["security_groups"][1]["id"]
        environment["security_groups"][1]["reachability"] = copy.deepcopy(
            assessments[second_group_id]
        )

        result = apply_network_reachability_context(
            environment,
            {first_group_id: assessments[first_group_id]},
        )

        self.assertEqual(1, len(result.warnings))
        self.assertIn("3 security group(s)", result.warnings[0])
        self.assertNotIn("reachability", result.environment["security_groups"][1])

    def test_context_referencing_absent_group_is_rejected(self):
        environment = load_aws_ec2_environment(EC2_PATH).environment
        assessments = load_network_reachability_context(CONTEXT_PATH)
        assessments["sg-absent"] = assessments.pop(next(iter(assessments)))

        with self.assertRaisesRegex(ValueError, "absent from the environment"):
            apply_network_reachability_context(environment, assessments)

    def test_duplicate_group_entries_are_rejected(self):
        payload = _payload()
        payload["security_groups"].append(copy.deepcopy(payload["security_groups"][0]))

        with self.assertRaisesRegex(ValueError, "duplicate security group"):
            normalize_network_reachability_context(payload)

    def test_schema_version_and_top_level_shape_are_validated(self):
        cases = (
            ({}, "unsupported schema version"),
            (
                {"schema_version": "2.0", "security_groups": []},
                "unsupported schema version",
            ),
            (
                {"schema_version": "1.0", "security_groups": []},
                "non-empty list",
            ),
            (
                {
                    "schema_version": "1.0",
                    "security_groups": [],
                    "unexpected": True,
                },
                "unsupported fields",
            ),
        )
        for payload, message in cases:
            with self.subTest(payload=payload), self.assertRaisesRegex(ValueError, message):
                normalize_network_reachability_context(payload)

    def test_method_timestamp_and_direction_values_are_validated(self):
        mutations = (
            ("method", "manual", "method must be one of"),
            ("observed_at", "2026-06-30", "UTC offset"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field):
                payload = _payload()
                payload["security_groups"][0][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    normalize_network_reachability_context(payload)

        payload = _payload()
        payload["security_groups"][0]["ingress"]["status"] = "safe"
        with self.assertRaisesRegex(ValueError, "status must be one of"):
            normalize_network_reachability_context(payload)

        payload = _payload()
        payload["security_groups"][0]["ingress"]["evidence"] = []
        with self.assertRaisesRegex(ValueError, "non-empty list"):
            normalize_network_reachability_context(payload)

        payload = _payload()
        payload["security_groups"][0]["ingress"]["scope"] = ""
        with self.assertRaisesRegex(ValueError, "non-empty scope"):
            normalize_network_reachability_context(payload)

        payload = _payload()
        evidence = payload["security_groups"][0]["ingress"]["evidence"]
        evidence.append(evidence[0])
        with self.assertRaisesRegex(ValueError, "duplicate values"):
            normalize_network_reachability_context(payload)

    def test_environment_group_shape_and_identity_are_validated(self):
        assessment = next(iter(load_network_reachability_context(CONTEXT_PATH).values()))
        cases = (
            ({}, "list of objects"),
            ({"security_groups": [{}]}, "non-empty id"),
            (
                {"security_groups": [{"id": "sg-a"}, {"id": "sg-a"}]},
                "duplicate security group",
            ),
        )
        for environment, message in cases:
            with self.subTest(environment=environment), self.assertRaisesRegex(
                ValueError,
                message,
            ):
                apply_network_reachability_context(environment, {"sg-a": assessment})

    def test_loader_rejects_non_object_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "context.json"
            path.write_text("[]", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "must contain a JSON object"):
                load_network_reachability_context(path)


if __name__ == "__main__":
    unittest.main()
