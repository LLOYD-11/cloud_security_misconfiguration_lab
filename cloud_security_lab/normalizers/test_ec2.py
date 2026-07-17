import copy
import json
import tempfile
import unittest
from pathlib import Path

from cloud_security_lab.normalizers.ec2 import (
    load_aws_ec2_environment,
    normalize_aws_ec2_environment,
)
from network_analyzer.analyzer import analyze_environment

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PATH = PROJECT_ROOT / "sample_data/aws/ec2/describe_security_groups.json"


def _response():
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


class NativeEc2NormalizerTests(unittest.TestCase):
    def test_native_sample_preserves_context_and_detects_expected_risks(self):
        result = load_aws_ec2_environment(SAMPLE_PATH)
        findings = analyze_environment(result.environment)

        self.assertEqual("111122223333", result.environment["account_id"])
        self.assertEqual(4, len(result.environment["security_groups"]))
        self.assertEqual(7, len(findings))
        self.assertEqual(
            ["NET-002", "NET-001", "NET-001", "NET-001", "NET-001", "NET-003", "NET-003"],
            [finding.rule_id for finding in findings],
        )
        self.assertTrue(
            all(finding.metadata["vpc_id"] == "vpc-00000000000000001" for finding in findings)
        )
        self.assertTrue(
            all(finding.metadata["owner_id"] == "111122223333" for finding in findings)
        )
        admin_group = result.environment["security_groups"][0]
        self.assertEqual("production", admin_group["tags"]["Environment"])
        self.assertTrue(admin_group["arn"].endswith("sg-00000000000000001"))

    def test_non_cidr_targets_are_preserved_with_visible_warnings(self):
        result = load_aws_ec2_environment(SAMPLE_PATH)
        internal_group = result.environment["security_groups"][3]

        self.assertEqual(
            {
                "protocol": "tcp",
                "from_port": 8080,
                "to_port": 8080,
                "description": "Application traffic from the load balancer",
                "peer_type": "security_group",
                "peer_id": "sg-00000000000000005",
                "peer_account_id": "111122223333",
                "peer_vpc_id": "vpc-00000000000000001",
                "peer_group_name": "load-balancer",
            },
            internal_group["inbound_rules"][0],
        )
        self.assertEqual("prefix_list", internal_group["outbound_rules"][0]["peer_type"])
        self.assertEqual(2, len(result.warnings))
        self.assertIn("prefix-list targets", result.warnings[0])
        self.assertIn("security-group targets", result.warnings[1])
        self.assertEqual([], analyze_environment({"security_groups": [internal_group]}))

    def test_paginated_response_is_rejected(self):
        response = _response()
        response["NextToken"] = "next-page"

        with self.assertRaisesRegex(ValueError, "collect all pages"):
            normalize_aws_ec2_environment(response)

        response = _response()
        response["NextToken"] = ""
        with self.assertRaisesRegex(ValueError, "non-empty string or null"):
            normalize_aws_ec2_environment(response)

        response = _response()
        response["NextToken"] = None
        self.assertEqual(4, len(normalize_aws_ec2_environment(response).environment["security_groups"]))

    def test_empty_or_missing_security_group_inventory_is_rejected(self):
        for response in ({}, {"SecurityGroups": []}):
            with self.subTest(response=response), self.assertRaisesRegex(
                ValueError, "SecurityGroups|at least one"
            ):
                normalize_aws_ec2_environment(response)

    def test_duplicate_security_groups_are_rejected(self):
        response = _response()
        response["SecurityGroups"].append(copy.deepcopy(response["SecurityGroups"][0]))

        with self.assertRaisesRegex(ValueError, "duplicate security group"):
            normalize_aws_ec2_environment(response)

    def test_multiple_owner_accounts_are_rejected(self):
        response = _response()
        response["SecurityGroups"][1]["OwnerId"] = "999988887777"
        response["SecurityGroups"][1]["SecurityGroupArn"] = (
            "arn:aws:ec2:us-east-1:999988887777:"
            "security-group/sg-00000000000000002"
        )

        with self.assertRaisesRegex(ValueError, "multiple owner account IDs"):
            normalize_aws_ec2_environment(response)

    def test_tcp_and_udp_port_bounds_are_validated(self):
        cases = (
            (None, 22, "requires integer port bounds"),
            (True, 22, "requires integer port bounds"),
            (23, 22, "within 0-65535 and ordered"),
            (-1, 22, "within 0-65535 and ordered"),
        )
        for from_port, to_port, message in cases:
            with self.subTest(from_port=from_port, to_port=to_port):
                response = _response()
                permission = response["SecurityGroups"][0]["IpPermissions"][0]
                permission["FromPort"] = from_port
                permission["ToPort"] = to_port
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_ec2_environment(response)

    def test_icmp_semantics_are_validated(self):
        cases = (
            (None, None, "requires both type and code"),
            (-1, 0, "requires code -1"),
            (256, 0, "between -1 and 255"),
        )
        for from_port, to_port, message in cases:
            with self.subTest(from_port=from_port, to_port=to_port):
                response = _response()
                permission = response["SecurityGroups"][0]["IpPermissions"][0]
                permission["IpProtocol"] = "icmp"
                permission["FromPort"] = from_port
                permission["ToPort"] = to_port
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_ec2_environment(response)

    def test_all_protocol_rule_discards_irrelevant_port_values(self):
        response = _response()
        permission = response["SecurityGroups"][2]["IpPermissions"][0]
        permission["FromPort"] = 22
        permission["ToPort"] = 22

        result = normalize_aws_ec2_environment(response)
        rule = result.environment["security_groups"][2]["inbound_rules"][0]

        self.assertIsNone(rule["from_port"])
        self.assertIsNone(rule["to_port"])

    def test_numeric_tcp_protocol_is_detected(self):
        response = _response()
        response["SecurityGroups"][0]["IpPermissions"][0]["IpProtocol"] = "06"

        result = normalize_aws_ec2_environment(response)
        findings = analyze_environment(result.environment)

        self.assertEqual(
            "6",
            result.environment["security_groups"][0]["inbound_rules"][0]["protocol"],
        )
        self.assertTrue(
            any(
                finding.rule_id == "NET-001" and finding.metadata.get("port") == "22"
                for finding in findings
            )
        )

    def test_invalid_protocol_name_or_number_is_rejected(self):
        for protocol in ("gre", "256", "-2"):
            with self.subTest(protocol=protocol):
                response = _response()
                response["SecurityGroups"][0]["IpPermissions"][0]["IpProtocol"] = protocol
                with self.assertRaisesRegex(ValueError, "IpProtocol"):
                    normalize_aws_ec2_environment(response)

    def test_malformed_or_wrong_family_cidr_is_rejected(self):
        cases = (
            ("CidrIp", "not-a-cidr", "not a valid CIDR"),
            ("CidrIp", "::/0", "not IPv4"),
            ("CidrIpv6", "0.0.0.0/0", "not IPv6"),
        )
        for field, value, message in cases:
            with self.subTest(field=field, value=value):
                response = _response()
                permission = response["SecurityGroups"][0]["IpPermissions"][0]
                if field == "CidrIpv6":
                    permission["IpRanges"] = []
                    permission["Ipv6Ranges"] = [{"CidrIpv6": value}]
                else:
                    permission["IpRanges"][0][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_ec2_environment(response)

    def test_permission_target_lists_and_presence_are_validated(self):
        response = _response()
        response["SecurityGroups"][0]["IpPermissions"][0]["IpRanges"] = {}
        with self.assertRaisesRegex(ValueError, "must be a list of objects"):
            normalize_aws_ec2_environment(response)

        response = _response()
        permission = response["SecurityGroups"][0]["IpPermissions"][0]
        for key in ("IpRanges", "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs"):
            permission[key] = []
        with self.assertRaisesRegex(ValueError, "has no CIDR"):
            normalize_aws_ec2_environment(response)

    def test_security_group_reference_fields_are_validated(self):
        cases = (
            ("GroupId", "", "GroupId"),
            ("UserId", "external", "12-digit"),
            ("VpcId", "vpc-example", "invalid AWS identifier"),
            ("VpcPeeringConnectionId", "pcx-example", "invalid AWS identifier"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                response = _response()
                pair = response["SecurityGroups"][3]["IpPermissions"][0][
                    "UserIdGroupPairs"
                ][0]
                pair[field] = value
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_ec2_environment(response)

    def test_peering_reference_context_is_preserved(self):
        response = _response()
        pair = response["SecurityGroups"][3]["IpPermissions"][0]["UserIdGroupPairs"][0]
        pair["VpcPeeringConnectionId"] = "pcx-00000000000000001"
        pair["PeeringStatus"] = "active"

        result = normalize_aws_ec2_environment(response)
        rule = result.environment["security_groups"][3]["inbound_rules"][0]

        self.assertEqual(
            "pcx-00000000000000001",
            rule["peer_vpc_peering_connection_id"],
        )
        self.assertEqual("active", rule["peering_status"])

    def test_security_group_arn_must_match_group_identity(self):
        cases = (
            ("arn:aws:ec2:us-east-1:111122223333:security-group/not-an-sg", "valid"),
            (
                "arn:aws:ec2:us-east-1:999988887777:security-group/sg-00000000000000001",
                "does not match",
            ),
            (
                "arn:aws:ec2:us-east-1:111122223333:security-group/sg-00000000000000009",
                "does not match",
            ),
        )
        for arn, message in cases:
            with self.subTest(arn=arn):
                response = _response()
                response["SecurityGroups"][0]["SecurityGroupArn"] = arn
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_ec2_environment(response)

    def test_duplicate_tags_are_rejected(self):
        response = _response()
        response["SecurityGroups"][0]["Tags"].append(
            {"Key": "Name", "Value": "duplicate"}
        )

        with self.assertRaisesRegex(ValueError, "duplicate tag key"):
            normalize_aws_ec2_environment(response)

    def test_loader_rejects_non_object_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "security-groups.json"
            path.write_text("[]", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "must contain a JSON object"):
                load_aws_ec2_environment(path)


if __name__ == "__main__":
    unittest.main()
