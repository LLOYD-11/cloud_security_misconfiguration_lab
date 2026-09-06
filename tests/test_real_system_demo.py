import json
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "demo" / "real-system" / "network-demo-stack.json"


class RealSystemDemoTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.template: dict[str, Any] = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        cls.resources: dict[str, Any] = cls.template["Resources"]

    def test_template_has_only_unattached_security_group(self) -> None:
        self.assertEqual(
            set(self.template),
            {
                "AWSTemplateFormatVersion",
                "Description",
                "Metadata",
                "Parameters",
                "Resources",
                "Outputs",
            },
        )
        self.assertEqual(set(self.resources), {"DemoSecurityGroup"})
        self.assertEqual(
            set(self.resources["DemoSecurityGroup"]),
            {"Type", "Properties"},
        )
        self.assertEqual(
            self.resources["DemoSecurityGroup"]["Type"],
            "AWS::EC2::SecurityGroup",
        )
        self.assertNotIn("DeletionPolicy", self.resources["DemoSecurityGroup"])
        self.assertNotIn("UpdateReplacePolicy", self.resources["DemoSecurityGroup"])

    def test_existing_vpc_is_an_explicit_parameter(self) -> None:
        self.assertEqual(
            self.template["Parameters"],
            {
                "VpcId": {
                    "Type": "AWS::EC2::VPC::Id",
                    "Description": (
                        "Existing authorized VPC in which to create the disposable "
                        "unattached group."
                    ),
                }
            },
        )
        self.assertNotIn("Transform", self.template)

    def test_ingress_is_limited_to_intentional_public_ssh(self) -> None:
        group = self.resources["DemoSecurityGroup"]["Properties"]
        self.assertEqual(
            set(group),
            {
                "GroupDescription",
                "VpcId",
                "SecurityGroupIngress",
                "SecurityGroupEgress",
                "Tags",
            },
        )
        self.assertEqual(group["VpcId"], {"Ref": "VpcId"})
        self.assertEqual(
            group["SecurityGroupIngress"],
            [
                {
                    "Description": "Intentional static analyzer input; no workload is attached",
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIp": "0.0.0.0/0",
                }
            ],
        )

    def test_egress_is_restricted_to_private_demo_range(self) -> None:
        group = self.resources["DemoSecurityGroup"]["Properties"]
        self.assertEqual(
            group["SecurityGroupEgress"],
            [
                {
                    "Description": "Private address range only",
                    "IpProtocol": "-1",
                    "CidrIp": "10.0.0.0/8",
                }
            ],
        )

        self.assertEqual(set(self.template["Outputs"]), {"SecurityGroupId"})
        self.assertEqual(
            self.template["Outputs"]["SecurityGroupId"]["Value"],
            {"Ref": "DemoSecurityGroup"},
        )


if __name__ == "__main__":
    unittest.main()
