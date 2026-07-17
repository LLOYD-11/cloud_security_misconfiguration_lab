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

        self.assertEqual(9, len(findings))
        self.assertIn("IAM-001", rule_ids)
        self.assertIn("IAM-002", rule_ids)
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
                                "action": "sts:AssumeRole",
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

    def test_external_principal_without_role_assumption_action_is_not_reported(self):
        environment = {
            "account_id": "111122223333",
            "users": [],
            "roles": [
                {
                    "name": "tag-session-only",
                    "attached_policies": [],
                    "trust_policy": {
                        "statements": [
                            {
                                "effect": "Allow",
                                "principal": {
                                    "AWS": "arn:aws:iam::999988887777:root"
                                },
                                "action": "sts:TagSession",
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

        self.assertEqual(["IAM-004", "IAM-002"], [finding.rule_id for finding in findings])

    def test_programmatic_user_without_console_password_does_not_require_mfa(self):
        environment = {
            "account_id": "111122223333",
            "users": [
                {
                    "name": "automation",
                    "password_enabled": False,
                    "mfa_enabled": False,
                    "access_keys": [],
                    "attached_policies": [],
                }
            ],
            "roles": [],
        }

        self.assertEqual([], analyze_environment(environment))

    def test_partial_action_and_resource_wildcards_remain_separate_findings(self):
        environment = {
            "account_id": "111122223333",
            "users": [],
            "roles": [
                {
                    "name": "audit-role",
                    "attached_policies": [
                        {
                            "policy_name": "AuditRead",
                            "statements": [
                                {
                                    "effect": "Allow",
                                    "action": ["iam:Get*", "iam:List*"],
                                    "resource": "*",
                                }
                            ],
                        }
                    ],
                    "trust_policy": {"statements": []},
                }
            ],
        }

        findings = analyze_environment(environment)

        self.assertEqual(
            ["IAM-002", "IAM-003"],
            [finding.rule_id for finding in findings],
        )
        self.assertEqual("medium", findings[0].severity)

    def test_not_action_and_not_resource_are_detected(self):
        environment = {
            "account_id": "111122223333",
            "users": [],
            "roles": [
                {
                    "name": "complement-role",
                    "attached_policies": [
                        {
                            "policy_name": "ComplementPolicy",
                            "statements": [
                                {
                                    "sid": "EverythingExceptIam",
                                    "effect": "Allow",
                                    "not_action": "iam:*",
                                    "resource": "*",
                                },
                                {
                                    "sid": "PassEveryOtherRole",
                                    "effect": "Allow",
                                    "action": "iam:PassRole",
                                    "not_resource": (
                                        "arn:aws:iam::111122223333:role/protected-role"
                                    ),
                                },
                            ],
                        }
                    ],
                    "trust_policy": {"statements": []},
                }
            ],
        }

        findings = analyze_environment(environment)

        self.assertEqual({"IAM-009", "IAM-010"}, {finding.rule_id for finding in findings})
        self.assertTrue(all(finding.severity == "high" for finding in findings))

    def test_group_policy_is_reported_once_with_member_context(self):
        environment = {
            "account_id": "111122223333",
            "users": [],
            "groups": [
                {
                    "name": "operators",
                    "members": ["alice", "bob"],
                    "attached_policies": [
                        {
                            "policy_name": "ServiceWildcard",
                            "statements": [
                                {
                                    "effect": "Allow",
                                    "action": "ec2:*",
                                    "resource": (
                                        "arn:aws:ec2:ap-southeast-2:111122223333:instance/*"
                                    ),
                                }
                            ],
                        }
                    ],
                }
            ],
            "roles": [],
        }

        findings = analyze_environment(environment)

        self.assertEqual(["IAM-002"], [finding.rule_id for finding in findings])
        self.assertEqual("group", findings[0].resource_type)
        self.assertEqual("2", findings[0].metadata["member_count"])
        self.assertEqual("alice, bob", findings[0].metadata["members"])

    def test_trust_guardrails_lower_severity_but_public_trust_remains_visible(self):
        environment = {
            "account_id": "111122223333",
            "users": [],
            "roles": [
                {
                    "name": "guarded-vendor-role",
                    "attached_policies": [],
                    "trust_policy": {
                        "statements": [
                            {
                                "effect": "Allow",
                                "principal": {
                                    "AWS": "arn:aws:iam::999988887777:root"
                                },
                                "action": "sts:AssumeRole",
                                "condition": {
                                    "StringEquals": {
                                        "sts:ExternalId": "customer-111122223333"
                                    }
                                },
                            }
                        ]
                    },
                },
                {
                    "name": "public-role",
                    "attached_policies": [],
                    "trust_policy": {
                        "statements": [
                            {
                                "effect": "Allow",
                                "principal": "*",
                                "action": "sts:AssumeRole",
                            }
                        ]
                    },
                },
                {
                    "name": "fake-guardrail-role",
                    "attached_policies": [],
                    "trust_policy": {
                        "statements": [
                            {
                                "effect": "Allow",
                                "principal": {
                                    "AWS": "arn:aws:iam::999988887777:root"
                                },
                                "action": "sts:AssumeRole",
                                "condition": {
                                    "Null": {
                                        "sts:ExternalId": "false"
                                    },
                                    "StringEquals": {
                                        "aws:PrincipalOrgID": False
                                    }
                                },
                            }
                        ]
                    },
                },
                {
                    "name": "not-principal-role",
                    "attached_policies": [],
                    "trust_policy": {
                        "statements": [
                            {
                                "effect": "Allow",
                                "not_principal": {
                                    "AWS": "arn:aws:iam::111122223333:role/blocked"
                                },
                                "action": "sts:AssumeRole",
                            }
                        ]
                    },
                },
            ],
        }

        findings = analyze_environment(environment)
        by_resource = {finding.resource_id: finding for finding in findings}

        self.assertEqual("medium", by_resource["guarded-vendor-role"].severity)
        self.assertEqual(
            "sts:ExternalId",
            by_resource["guarded-vendor-role"].metadata["trust_guardrails"],
        )
        self.assertEqual("critical", by_resource["public-role"].severity)
        self.assertEqual("high", by_resource["fake-guardrail-role"].severity)
        self.assertEqual(
            "none",
            by_resource["fake-guardrail-role"].metadata["trust_guardrails"],
        )
        self.assertEqual("critical", by_resource["not-principal-role"].severity)
        self.assertIn("all principals except", by_resource["not-principal-role"].evidence)

    def test_stale_credentials_are_distinct_from_rotation_age(self):
        environment = {
            "account_id": "111122223333",
            "users": [
                {
                    "name": "legacy-automation",
                    "password_enabled": False,
                    "mfa_enabled": False,
                    "access_keys": [
                        {
                            "id": "credential-report:key-1",
                            "status": "Active",
                            "age_days": 180,
                            "last_used_days": None,
                        }
                    ],
                    "attached_policies": [],
                },
                {
                    "name": "dormant-console",
                    "password_enabled": True,
                    "password_age_days": 200,
                    "password_last_used_days": 120,
                    "mfa_enabled": True,
                    "access_keys": [],
                    "attached_policies": [],
                },
            ],
            "roles": [],
        }

        findings = analyze_environment(environment)
        signatures = {(finding.rule_id, finding.resource_id) for finding in findings}

        self.assertEqual(
            {
                ("IAM-007", "legacy-automation"),
                ("IAM-011", "legacy-automation"),
                ("IAM-012", "dormant-console"),
            },
            signatures,
        )
        self.assertNotIn(("IAM-006", "legacy-automation"), signatures)

    def test_root_credentials_and_unrestricted_boundary_are_detected(self):
        environment = {
            "account_id": "111122223333",
            "root_account": {
                "password_enabled": True,
                "password_age_days": 300,
                "password_last_used_days": 1,
                "mfa_enabled": False,
                "access_keys": [
                    {
                        "id": "credential-report:key-1",
                        "status": "Active",
                        "age_days": 30,
                        "last_used_days": 1,
                    }
                ],
            },
            "users": [],
            "roles": [
                {
                    "name": "delegated-admin",
                    "attached_policies": [],
                    "trust_policy": {"statements": []},
                    "permissions_boundary": {
                        "policy_arn": (
                            "arn:aws:iam::111122223333:policy/UnrestrictedBoundary"
                        ),
                        "policy_name": "UnrestrictedBoundary",
                        "document_available": True,
                        "statements": [
                            {
                                "effect": "Allow",
                                "action": "*",
                                "resource": "*",
                            }
                        ],
                    },
                }
            ],
        }

        findings = analyze_environment(environment)

        self.assertEqual(
            {"IAM-013", "IAM-014", "IAM-015"},
            {finding.rule_id for finding in findings},
        )
        boundary_finding = next(
            finding for finding in findings if finding.rule_id == "IAM-015"
        )
        self.assertIn("UnrestrictedBoundary", boundary_finding.metadata["permissions_boundary"])

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
        self.assertEqual("2.0", payload["schema_version"])
        self.assertEqual(findings_to_dicts(findings), payload["findings"])


if __name__ == "__main__":
    unittest.main()
