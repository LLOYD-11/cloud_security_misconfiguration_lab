import json
import tempfile
import unittest
from pathlib import Path

from iam_analyzer.analyzer import (
    analyze_environment,
    findings_to_dicts,
    load_environment,
    write_findings,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FILE = PROJECT_ROOT / "sample_data" / "iam" / "sample_iam_environment.json"


class AnalyzerTests(unittest.TestCase):
    def test_sample_environment_detects_expected_risks(self):
        environment = load_environment(SAMPLE_FILE)

        findings = analyze_environment(environment)
        rule_ids = {finding.rule_id for finding in findings}
        sample_finding = findings[0]

        self.assertIn("IAM-001", rule_ids)
        self.assertIn("IAM-003", rule_ids)
        self.assertIn("IAM-004", rule_ids)
        self.assertIn("IAM-005", rule_ids)
        self.assertIn("IAM-006", rule_ids)
        self.assertIn("IAM-007", rule_ids)
        self.assertIn("IAM-008", rule_ids)
        self.assertEqual("iam", sample_finding.module)
        self.assertEqual("identity-and-access", sample_finding.category)
        self.assertTrue(sample_finding.title)
        self.assertTrue(sample_finding.resource_type)
        self.assertTrue(sample_finding.resource_id)

    def test_readonly_user_with_mfa_has_no_findings(self):
        environment = {
            "account_id": "111122223333",
            "users": [
                {
                    "name": "readonly",
                    "mfa_enabled": True,
                    "access_keys": [],
                    "attached_policies": [
                        {
                            "policy_name": "ScopedRead",
                            "statements": [
                                {
                                    "sid": "ReadOnly",
                                    "effect": "Allow",
                                    "action": ["s3:GetObject"],
                                    "resource": "arn:aws:s3:::company-reports/monthly.csv",
                                }
                            ],
                        }
                    ],
                }
            ],
            "roles": [],
        }

        findings = analyze_environment(environment)

        self.assertEqual([], findings)

    def test_external_trust_detection_ignores_same_account_role(self):
        environment = {
            "account_id": "111122223333",
            "users": [],
            "roles": [
                {
                    "name": "internal-role",
                    "trust_policy": {
                        "statements": [
                            {
                                "sid": "InternalTrust",
                                "effect": "Allow",
                                "principal": {
                                    "AWS": "arn:aws:iam::111122223333:root"
                                },
                                "action": "sts:AssumeRole",
                            }
                        ]
                    },
                    "attached_policies": [],
                }
            ],
        }

        findings = analyze_environment(environment)

        self.assertEqual([], findings)

    def test_findings_export_writes_json_payload(self):
        environment = load_environment(SAMPLE_FILE)
        findings = analyze_environment(environment)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "findings.json"
            write_findings(output_path, findings)

            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(len(findings), payload["finding_count"])
        self.assertEqual("1.0", payload["schema_version"])
        self.assertEqual(findings_to_dicts(findings), payload["findings"])


if __name__ == "__main__":
    unittest.main()
