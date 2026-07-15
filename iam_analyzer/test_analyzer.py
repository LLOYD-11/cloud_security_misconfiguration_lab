import json
import tempfile
import unittest
from pathlib import Path

from cloud_findings import findings_to_dicts, write_findings
from iam_analyzer.analyzer import (
    analyze_environment,
    load_environment,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FILE = PROJECT_ROOT / "sample_data" / "iam" / "sample_iam_environment.json"


class AnalyzerTests(unittest.TestCase):
    def test_sample_environment_detects_expected_risks(self):
        environment = load_environment(SAMPLE_FILE)

        findings = analyze_environment(environment)
        rule_ids = {finding.rule_id for finding in findings}
        sample_finding = findings[0]

        self.assertEqual(8, len(findings))
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
        self.assertTrue(all(finding.references for finding in findings))

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

    def test_mixed_same_account_and_external_trust_detects_external_principal(self):
        environment = {
            "account_id": "111122223333",
            "users": [],
            "roles": [
                {
                    "name": "mixed-trust-role",
                    "attached_policies": [],
                    "trust_policy": {
                        "statements": [
                            {
                                "effect": "Allow",
                                "principal": {
                                    "AWS": [
                                        "arn:aws:iam::111122223333:root",
                                        "arn:aws:iam::999988887777:root",
                                    ]
                                },
                            }
                        ]
                    },
                }
            ],
        }

        findings = analyze_environment(environment)

        self.assertEqual(["IAM-008"], [finding.rule_id for finding in findings])
        self.assertIn("999988887777", findings[0].evidence)

    def test_service_principal_is_not_reported_as_cross_account_trust(self):
        environment = {
            "account_id": "111122223333",
            "users": [],
            "roles": [
                {
                    "name": "lambda-execution-role",
                    "attached_policies": [],
                    "trust_policy": {
                        "statements": [
                            {
                                "effect": "Allow",
                                "principal": {"Service": "lambda.amazonaws.com"},
                            }
                        ]
                    },
                }
            ],
        }

        self.assertEqual([], analyze_environment(environment))

    def test_mfa_condition_requires_true_value_for_mfa_key(self):
        environment = {
            "account_id": "111122223333",
            "users": [
                {
                    "name": "condition-test",
                    "mfa_enabled": True,
                    "access_keys": [],
                    "attached_policies": [
                        {
                            "policy_name": "SensitiveChange",
                            "statements": [
                                {
                                    "effect": "Allow",
                                    "action": "iam:CreateUser",
                                    "resource": "arn:aws:iam::111122223333:user/*",
                                    "condition": {
                                        "Bool": {
                                            "aws:MultiFactorAuthPresent": "false",
                                            "aws:SecureTransport": "true",
                                        }
                                    },
                                }
                            ],
                        }
                    ],
                }
            ],
            "roles": [],
        }

        findings = analyze_environment(environment)

        self.assertEqual(["IAM-005"], [finding.rule_id for finding in findings])

    def test_s3_write_wildcard_action_is_detected(self):
        environment = {
            "account_id": "111122223333",
            "users": [
                {
                    "name": "s3-writer",
                    "mfa_enabled": True,
                    "access_keys": [],
                    "attached_policies": [
                        {
                            "policy_name": "WildcardWrite",
                            "statements": [
                                {
                                    "effect": "Allow",
                                    "action": "s3:Put*",
                                    "resource": "arn:aws:s3:::company-*/*",
                                }
                            ],
                        }
                    ],
                }
            ],
            "roles": [],
        }

        findings = analyze_environment(environment)

        self.assertEqual(["IAM-004"], [finding.rule_id for finding in findings])

    def test_readonly_role_does_not_require_mfa_in_identity_policy(self):
        environment = {
            "account_id": "111122223333",
            "users": [],
            "roles": [
                {
                    "name": "readonly-role",
                    "attached_policies": [
                        {
                            "policy_name": "ReadOnly",
                            "statements": [
                                {
                                    "effect": "Allow",
                                    "action": ["iam:GetUser", "iam:ListUsers"],
                                    "resource": "arn:aws:iam::111122223333:user/example",
                                }
                            ],
                        }
                    ],
                    "trust_policy": {"statements": []},
                }
            ],
        }

        self.assertEqual([], analyze_environment(environment))

    def test_inactive_old_access_key_is_not_reported(self):
        environment = {
            "account_id": "111122223333",
            "users": [
                {
                    "name": "retired-key-user",
                    "mfa_enabled": True,
                    "access_keys": [
                        {
                            "id": "AKIAEXAMPLEINACTIVE",
                            "status": "Inactive",
                            "age_days": 400,
                        }
                    ],
                    "attached_policies": [],
                }
            ],
            "roles": [],
        }

        self.assertEqual([], analyze_environment(environment))

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
