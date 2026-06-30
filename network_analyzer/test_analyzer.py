import json
import tempfile
import unittest
from pathlib import Path

from cloud_findings import findings_to_dicts, write_findings
from network_analyzer.analyzer import analyze_environment, load_environment


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FILE = PROJECT_ROOT / "sample_data" / "network" / "sample_network_environment.json"


class NetworkAnalyzerTests(unittest.TestCase):
    def test_sample_environment_detects_expected_network_risks(self):
        environment = load_environment(SAMPLE_FILE)

        findings = analyze_environment(environment)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("NET-001", rule_ids)
        self.assertIn("NET-002", rule_ids)
        self.assertIn("NET-003", rule_ids)
        self.assertTrue(all(finding.module == "network" for finding in findings))
        self.assertTrue(all(finding.category == "network-exposure" for finding in findings))
        self.assertTrue(all(finding.references for finding in findings))

    def test_private_security_group_has_no_findings(self):
        environment = {
            "security_groups": [
                {
                    "id": "sg-private",
                    "name": "private-app",
                    "inbound_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 22,
                            "to_port": 22,
                            "cidr": "10.0.0.0/16",
                        }
                    ],
                    "outbound_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 443,
                            "to_port": 443,
                            "cidr": "10.0.0.0/16",
                        }
                    ],
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertEqual([], findings)

    def test_public_port_range_covering_sensitive_port_is_detected(self):
        environment = {
            "security_groups": [
                {
                    "id": "sg-range",
                    "name": "range-open",
                    "inbound_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 3300,
                            "to_port": 3310,
                            "cidr": "0.0.0.0/0",
                        }
                    ],
                    "outbound_rules": [],
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertEqual(["NET-001"], [finding.rule_id for finding in findings])
        self.assertEqual("3306", findings[0].metadata["port"])

    def test_all_protocol_public_inbound_does_not_duplicate_sensitive_ports(self):
        environment = {
            "security_groups": [
                {
                    "id": "sg-all",
                    "name": "all-open",
                    "inbound_rules": [
                        {
                            "protocol": "-1",
                            "from_port": None,
                            "to_port": None,
                            "cidr": "0.0.0.0/0",
                        }
                    ],
                    "outbound_rules": [],
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertEqual(["NET-002"], [finding.rule_id for finding in findings])

    def test_findings_export_writes_shared_schema(self):
        environment = load_environment(SAMPLE_FILE)
        findings = analyze_environment(environment)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "network_findings.json"
            write_findings(output_path, findings)
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual("1.0", payload["schema_version"])
        self.assertEqual(len(findings), payload["finding_count"])
        self.assertEqual(findings_to_dicts(findings), payload["findings"])


if __name__ == "__main__":
    unittest.main()
