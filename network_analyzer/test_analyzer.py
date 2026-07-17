import json
import tempfile
import unittest
from pathlib import Path

from cloud_findings import findings_to_dicts, write_findings
from network_analyzer.analyzer import SERVICE_CATALOG, analyze_environment, load_environment

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FILE = PROJECT_ROOT / "sample_data" / "network" / "sample_network_environment.json"


class NetworkAnalyzerTests(unittest.TestCase):
    def test_sample_environment_detects_expected_network_risks(self):
        environment = load_environment(SAMPLE_FILE)

        findings = analyze_environment(environment)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertEqual(10, len(findings))
        self.assertIn("NET-001", rule_ids)
        self.assertIn("NET-002", rule_ids)
        self.assertIn("NET-003", rule_ids)
        self.assertTrue(all(finding.module == "network" for finding in findings))
        self.assertTrue(all(finding.category == "network-exposure" for finding in findings))
        self.assertTrue(all(finding.references for finding in findings))
        self.assertTrue(
            all("reachability_status" in finding.metadata for finding in findings)
        )

    def test_service_catalog_covers_multiple_cloud_workload_categories(self):
        services = {service.port: service for service in SERVICE_CATALOG}

        self.assertGreaterEqual(len(services), 20)
        self.assertEqual("critical", services[2375].severity)
        self.assertEqual("control-plane", services[6443].category)
        self.assertEqual("database", services[27017].category)
        self.assertEqual(frozenset({"tcp", "udp"}), services[3389].protocols)
        self.assertEqual(len(SERVICE_CATALOG), len(services))

    def test_sample_reachability_context_changes_confidence_without_hiding_risk(self):
        findings = analyze_environment(load_environment(SAMPLE_FILE))
        by_port = {
            finding.metadata["port"]: finding
            for finding in findings
            if finding.rule_id == "NET-001"
        }

        self.assertEqual("critical", by_port["2375"].severity)
        self.assertEqual("reachable", by_port["2375"].metadata["reachability_status"])
        self.assertEqual("high", by_port["6379"].severity)
        self.assertEqual(
            "critical",
            by_port["6379"].metadata["service_default_severity"],
        )
        self.assertEqual(
            "not_reachable",
            by_port["6379"].metadata["reachability_status"],
        )
        self.assertEqual("medium", by_port["3306"].severity)
        self.assertIn("latent risk", by_port["3306"].impact)

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

    def test_missing_group_name_uses_resource_id_in_metadata(self):
        environment = {
            "security_groups": [
                {
                    "id": "sg-legacy",
                    "inbound_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 22,
                            "to_port": 22,
                            "cidr": "0.0.0.0/0",
                        }
                    ],
                    "outbound_rules": [],
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertEqual("sg-legacy", findings[0].metadata["group_name"])

    def test_udp_database_port_is_not_reported_as_tcp_database_service(self):
        environment = {
            "security_groups": [
                {
                    "id": "sg-udp",
                    "name": "udp-range",
                    "inbound_rules": [
                        {
                            "protocol": "udp",
                            "from_port": 3306,
                            "to_port": 3306,
                            "cidr": "0.0.0.0/0",
                        }
                    ],
                    "outbound_rules": [],
                }
            ]
        }

        self.assertEqual([], analyze_environment(environment))

    def test_broad_public_cidr_is_detected(self):
        environment = {
            "security_groups": [
                {
                    "id": "sg-broad",
                    "name": "broad-range",
                    "inbound_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 22,
                            "to_port": 22,
                            "cidr": "0.0.0.0/1",
                        }
                    ],
                    "outbound_rules": [],
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertEqual(["NET-001"], [finding.rule_id for finding in findings])
        self.assertEqual("broad-public", findings[0].metadata["exposure_scope"])

    def test_private_slash_eight_is_not_reported_as_broad_public(self):
        environment = {
            "security_groups": [
                {
                    "id": "sg-private",
                    "name": "private-range",
                    "inbound_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 22,
                            "to_port": 22,
                            "cidr": "10.0.0.0/8",
                        }
                    ],
                    "outbound_rules": [],
                }
            ]
        }

        self.assertEqual([], analyze_environment(environment))

    def test_findings_export_writes_shared_schema(self):
        environment = load_environment(SAMPLE_FILE)
        findings = analyze_environment(environment)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "network_findings.json"
            write_findings(output_path, findings)
            payload = json.loads(output_path.read_text(encoding="utf-8"))

            self.assertEqual("2.0", payload["schema_version"])
        self.assertEqual(len(findings), payload["finding_count"])
        self.assertEqual(findings_to_dicts(findings), payload["findings"])

    def test_not_reachable_context_deescalates_but_retains_finding(self):
        environment = {
            "security_groups": [
                {
                    "id": "sg-latent",
                    "name": "latent-admin",
                    "reachability": {
                        "method": "manual-topology-review",
                        "observed_at": "2026-06-30T00:00:00Z",
                        "ingress": {
                            "status": "not_reachable",
                            "scope": "All public IPv4 ingress rules.",
                            "evidence": ["No public address or internet gateway route."],
                            "resource_ids": ["eni-example"],
                        },
                        "egress": {
                            "status": "not_reachable",
                            "scope": "All public IPv4 egress rules.",
                            "evidence": ["No NAT or internet gateway route."],
                            "resource_ids": [],
                        },
                    },
                    "inbound_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 2375,
                            "to_port": 2375,
                            "cidr": "0.0.0.0/0",
                        }
                    ],
                    "outbound_rules": [
                        {
                            "protocol": "-1",
                            "from_port": None,
                            "to_port": None,
                            "cidr": "0.0.0.0/0",
                        }
                    ],
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertEqual(["high", "low"], [finding.severity for finding in findings])
        self.assertTrue(
            all(
                finding.metadata["reachability_status"] == "not_reachable"
                for finding in findings
            )
        )

    def test_missing_or_malformed_context_never_claims_reachability(self):
        base_group = {
            "id": "sg-unverified",
            "name": "unverified",
            "inbound_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 6443,
                    "to_port": 6443,
                    "cidr": "0.0.0.0/0",
                }
            ],
            "outbound_rules": [],
        }
        for reachability, expected_status in (
            (None, "not_assessed"),
            ({"ingress": {"status": "not_reachable"}}, "inconclusive"),
            (
                {
                    "method": "unsupported",
                    "observed_at": "2026-06-30T00:00:00Z",
                    "ingress": {
                        "status": "not_reachable",
                        "scope": "All public IPv4 ingress rules.",
                        "evidence": ["No public path."],
                    },
                },
                "inconclusive",
            ),
            (
                {
                    "method": "manual-topology-review",
                    "observed_at": "2026-06-30T00:00:00",
                    "ingress": {
                        "status": "not_reachable",
                        "scope": "All public IPv4 ingress rules.",
                        "evidence": ["No public path."],
                    },
                },
                "inconclusive",
            ),
        ):
            with self.subTest(reachability=reachability):
                group = dict(base_group)
                if reachability is not None:
                    group["reachability"] = reachability
                finding = analyze_environment({"security_groups": [group]})[0]

                self.assertEqual("high", finding.severity)
                self.assertEqual(
                    expected_status,
                    finding.metadata["reachability_status"],
                )

    def test_expanded_port_range_can_identify_multiple_control_plane_services(self):
        environment = {
            "security_groups": [
                {
                    "id": "sg-control-plane",
                    "name": "control-plane",
                    "inbound_rules": [
                        {
                            "protocol": "tcp",
                            "from_port": 2379,
                            "to_port": 2380,
                            "cidr": "0.0.0.0/0",
                        }
                    ],
                    "outbound_rules": [],
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertEqual(2, len(findings))
        self.assertEqual(
            {"etcd client API", "etcd peer API"},
            {finding.metadata["service"] for finding in findings},
        )


if __name__ == "__main__":
    unittest.main()
