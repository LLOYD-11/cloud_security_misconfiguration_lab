import copy
import tempfile
import unittest
from pathlib import Path

from cloud_inputs import (
    SimplifiedInputError,
    load_simplified_environment,
    validate_simplified_environment,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = {
    "iam": PROJECT_ROOT / "sample_data/iam/sample_iam_environment.json",
    "storage": PROJECT_ROOT
    / "sample_data/storage/sample_storage_environment.json",
    "network": PROJECT_ROOT
    / "sample_data/network/sample_network_environment.json",
    "cloudtrail": PROJECT_ROOT
    / "sample_data/cloudtrail/sample_cloudtrail_events.json",
}
MINIMAL_ENVIRONMENTS = {
    "iam": {
        "account_id": "111122223333",
        "users": [],
        "roles": [],
    },
    "storage": {
        "account_id": "111122223333",
        "buckets": [],
    },
    "network": {
        "account_id": "111122223333",
        "security_groups": [],
    },
    "cloudtrail": {
        "account_id": "111122223333",
        "events": [],
    },
}


class SimplifiedInputValidationTests(unittest.TestCase):
    def test_committed_samples_pass_runtime_validation(self):
        for module, path in SAMPLES.items():
            with self.subTest(module=module):
                environment = load_simplified_environment(path, module)
                self.assertEqual("111122223333", environment["account_id"])

    def test_minimal_environments_pass_runtime_validation(self):
        for module, environment in MINIMAL_ENVIRONMENTS.items():
            with self.subTest(module=module):
                self.assertIs(
                    environment,
                    validate_simplified_environment(module, environment),
                )

    def test_each_module_rejects_a_malformed_primary_container(self):
        cases = {
            "iam": (
                {"account_id": "111122223333", "users": {}, "roles": []},
                "Invalid simplified IAM input at $.users: expected an array.",
            ),
            "storage": (
                {"account_id": "111122223333", "buckets": {}},
                "Invalid simplified storage input at $.buckets: expected an array.",
            ),
            "network": (
                {"account_id": "111122223333", "security_groups": {}},
                "Invalid simplified network input at $.security_groups: expected an array.",
            ),
            "cloudtrail": (
                {"account_id": "111122223333", "events": {}},
                "Invalid simplified CloudTrail input at $.events: expected an array.",
            ),
        }
        for module, (environment, message) in cases.items():
            with self.subTest(module=module), self.assertRaises(
                SimplifiedInputError
            ) as context:
                validate_simplified_environment(module, environment)
            self.assertEqual(message, str(context.exception))

    def test_iam_rejects_nested_policy_container_with_stable_path(self):
        environment = {
            "account_id": "111122223333",
            "users": [
                {
                    "name": "alice",
                    "mfa_enabled": True,
                    "access_keys": [],
                    "attached_policies": {},
                }
            ],
            "roles": [],
        }
        with self.assertRaisesRegex(
            SimplifiedInputError,
            r"at \$\.users\[0\]\.attached_policies: expected an array",
        ):
            validate_simplified_environment("iam", environment)

    def test_iam_accepts_unambiguous_aws_statement_aliases(self):
        environment = copy.deepcopy(MINIMAL_ENVIRONMENTS["iam"])
        environment["roles"] = [
            {
                "name": "compatibility-role",
                "trust_policy": {
                    "document": {
                        "Version": "2012-10-17",
                        "Id": "CompatibilityTrustPolicy",
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                        },
                    }
                },
                "attached_policies": [],
            }
        ]
        validate_simplified_environment("iam", environment)

    def test_iam_rejects_ambiguous_statement_aliases(self):
        environment = copy.deepcopy(MINIMAL_ENVIRONMENTS["iam"])
        environment["roles"] = [
            {
                "name": "ambiguous-role",
                "trust_policy": {
                    "statements": [
                        {
                            "effect": "Allow",
                            "Effect": "Deny",
                            "action": "sts:AssumeRole",
                        }
                    ]
                },
                "attached_policies": [],
            }
        ]
        with self.assertRaisesRegex(
            SimplifiedInputError,
            "must not define both 'effect' and 'Effect'",
        ):
            validate_simplified_environment("iam", environment)

    def test_iam_rejects_mutually_exclusive_statement_elements(self):
        conflicting_pairs = (
            ({"action": "*", "not_action": "iam:*"}, "action/Action"),
            (
                {"action": "*", "resource": "*", "not_resource": "example"},
                "resource/Resource",
            ),
            (
                {
                    "action": "sts:AssumeRole",
                    "principal": "*",
                    "not_principal": {"AWS": "111122223333"},
                },
                "principal/Principal",
            ),
        )
        for fields, message in conflicting_pairs:
            environment = copy.deepcopy(MINIMAL_ENVIRONMENTS["iam"])
            environment["roles"] = [
                {
                    "name": "ambiguous-role",
                    "trust_policy": {
                        "statements": [{"effect": "Allow", **fields}]
                    },
                    "attached_policies": [],
                }
            ]
            with self.subTest(message=message), self.assertRaisesRegex(
                SimplifiedInputError,
                message,
            ):
                validate_simplified_environment("iam", environment)

    def test_storage_rejects_non_boolean_public_access_control(self):
        environment = {
            "account_id": "111122223333",
            "buckets": [
                {
                    "name": "example-bucket",
                    "public_access_block": {
                        "block_public_acls": "true",
                        "ignore_public_acls": True,
                        "block_public_policy": True,
                        "restrict_public_buckets": True,
                    },
                    "acl": {"grants": []},
                    "bucket_policy": {"statements": []},
                    "encryption": {"enabled": True},
                    "versioning": {"status": "Enabled"},
                }
            ],
        }
        with self.assertRaisesRegex(
            SimplifiedInputError,
            r"at \$\.buckets\[0\]\.public_access_block\.block_public_acls: "
            "expected a boolean",
        ):
            validate_simplified_environment("storage", environment)

    def test_storage_accepts_unambiguous_aws_statement_aliases(self):
        environment = {
            "account_id": "111122223333",
            "buckets": [
                {
                    "name": "compatibility-bucket",
                    "public_access_block": {
                        "block_public_acls": True,
                        "ignore_public_acls": True,
                        "block_public_policy": True,
                        "restrict_public_buckets": True,
                    },
                    "acl": {"grants": []},
                    "bucket_policy": {
                        "Version": "2012-10-17",
                        "Id": "CompatibilityBucketPolicy",
                        "Statement": {
                            "Effect": "Allow",
                            "Principal": {"AWS": "111122223333"},
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::compatibility-bucket/*",
                        }
                    },
                    "encryption": {"enabled": True},
                    "versioning": {"status": "Enabled"},
                }
            ],
        }
        validate_simplified_environment("storage", environment)

    def test_network_rejects_invalid_cidr_and_inverted_port_range(self):
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
                            "to_port": 80,
                            "cidr": "public",
                        }
                    ],
                    "outbound_rules": [],
                }
            ],
        }
        with self.assertRaisesRegex(
            SimplifiedInputError,
            "expected from_port to be less than or equal to to_port",
        ):
            validate_simplified_environment("network", environment)

        environment["security_groups"][0]["inbound_rules"][0]["from_port"] = 80
        with self.assertRaisesRegex(
            SimplifiedInputError,
            r"at \$\.security_groups\[0\]\.inbound_rules\[0\]\.cidr: "
            "expected a valid IPv4 or IPv6 CIDR",
        ):
            validate_simplified_environment("network", environment)

    def test_network_accepts_unambiguous_legacy_cidr_aliases(self):
        environment = {
            "account_id": "111122223333",
            "security_groups": [
                {
                    "id": "sg-example",
                    "name": "example",
                    "inbound_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 22,
                            "to_port": 22,
                            "cidr_ip": "0.0.0.0/0",
                        },
                        {
                            "protocol": "tcp",
                            "from_port": 3389,
                            "to_port": 3389,
                            "cidr_ipv6": "::/0",
                        },
                    ],
                    "outbound_rules": [],
                }
            ],
        }
        validate_simplified_environment("network", environment)

        environment["security_groups"][0]["inbound_rules"][0]["cidr"] = (
            "0.0.0.0/0"
        )
        with self.assertRaisesRegex(
            SimplifiedInputError,
            "must not define more than one of 'cidr', 'cidr_ip', and 'cidr_ipv6'",
        ):
            validate_simplified_environment("network", environment)

    def test_cloudtrail_rejects_invalid_timestamp_and_nested_container(self):
        event = {
            "eventTime": "2026-06-30 01:00:00",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "sourceIPAddress": "192.0.2.1",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
            "requestParameters": [],
        }
        environment = {
            "account_id": "111122223333",
            "events": [event],
        }
        with self.assertRaisesRegex(
            SimplifiedInputError,
            r"at \$\.events\[0\]\.eventTime: expected an RFC 3339 timestamp",
        ):
            validate_simplified_environment("cloudtrail", environment)

        event["eventTime"] = "2026-06-30T01:00:00Z"
        with self.assertRaisesRegex(
            SimplifiedInputError,
            r"at \$\.events\[0\]\.requestParameters: expected an object",
        ):
            validate_simplified_environment("cloudtrail", environment)

    def test_cloudtrail_accepts_schema_supported_timestamp_separators(self):
        event = {
            "eventTime": "2026-06-30t01:00:00z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "sourceIPAddress": "192.0.2.1",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
        }
        environment = {
            "account_id": "111122223333",
            "events": [event],
        }
        validate_simplified_environment("cloudtrail", environment)
        self.assertEqual("2026-06-30T01:00:00Z", event["eventTime"])

        event["eventTime"] = "2026-06-30 11:00:00+10:00"
        validate_simplified_environment("cloudtrail", environment)
        self.assertEqual("2026-06-30T01:00:00Z", event["eventTime"])

        event["eventTime"] = "2026-02-30T01:00:00Z"
        with self.assertRaisesRegex(
            SimplifiedInputError,
            r"at \$\.events\[0\]\.eventTime: expected an RFC 3339 timestamp",
        ):
            validate_simplified_environment("cloudtrail", environment)

        event["eventTime"] = "0001-01-01T00:00:00+23:59"
        with self.assertRaisesRegex(
            SimplifiedInputError,
            r"at \$\.events\[0\]\.eventTime: expected an RFC 3339 timestamp",
        ):
            validate_simplified_environment("cloudtrail", environment)

        event["eventTime"] = "2026-06-30T01:00:00-00:00"
        with self.assertRaisesRegex(
            SimplifiedInputError,
            r"at \$\.events\[0\]\.eventTime: expected an RFC 3339 timestamp",
        ):
            validate_simplified_environment("cloudtrail", environment)

    def test_network_canonicalizes_embedded_reachability_timestamp(self):
        direction = {
            "status": "not_reachable",
            "scope": "All documented public rules.",
            "evidence": ["No complete path was found."],
        }
        environment = {
            "account_id": "111122223333",
            "security_groups": [
                {
                    "id": "sg-example",
                    "name": "example",
                    "reachability": {
                        "method": "manual-topology-review",
                        "observed_at": "2026-06-30T11:00:00+10:00",
                        "ingress": dict(direction),
                        "egress": dict(direction),
                    },
                    "inbound_rules": [],
                    "outbound_rules": [],
                }
            ],
        }
        validate_simplified_environment("network", environment)

        self.assertEqual(
            "2026-06-30T01:00:00Z",
            environment["security_groups"][0]["reachability"]["observed_at"],
        )

    def test_unknown_fields_are_rejected_deterministically(self):
        environment = {
            **MINIMAL_ENVIRONMENTS["storage"],
            "z_typo": True,
            "a_typo": True,
        }
        with self.assertRaisesRegex(
            SimplifiedInputError,
            r"at \$\.a_typo: unsupported field",
        ):
            validate_simplified_environment("storage", environment)

    def test_invalid_json_is_wrapped_in_a_stable_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "invalid.json"
            path.write_text('{"users": ]', encoding="utf-8")

            with self.assertRaisesRegex(
                SimplifiedInputError,
                r"^Invalid simplified IAM input at \$: invalid JSON at line 1 column 11\.$",
            ):
                load_simplified_environment(path, "iam")

    def test_unknown_module_is_rejected(self):
        with self.assertRaisesRegex(
            ValueError,
            "Unsupported simplified-input module 'unknown'",
        ):
            validate_simplified_environment("unknown", {})

        with self.assertRaisesRegex(
            ValueError,
            "Unsupported simplified-input module 'unknown'",
        ):
            load_simplified_environment(Path("does-not-exist.json"), "unknown")


if __name__ == "__main__":
    unittest.main()
