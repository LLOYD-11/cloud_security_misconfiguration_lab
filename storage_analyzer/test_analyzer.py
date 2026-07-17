import json
import tempfile
import unittest
from pathlib import Path

from cloud_findings import findings_to_dicts, write_findings
from storage_analyzer.analyzer import analyze_environment, load_environment

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FILE = PROJECT_ROOT / "sample_data" / "storage" / "sample_storage_environment.json"


def _policy_environment(
    condition,
    *,
    use_not_principal=False,
):
    statement = {
        "effect": "Allow",
        "principal": "*",
        "action": "s3:GetObject",
        "resource": "arn:aws:s3:::condition-test/*",
    }
    if condition is not None:
        statement["condition"] = condition
    if use_not_principal:
        statement["not_principal"] = {"AWS": "arn:aws:iam::111122223333:root"}
        del statement["principal"]
    return {
        "buckets": [
            {
                "name": "condition-test",
                "public_access_block": {
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": True,
                    "restrict_public_buckets": False,
                },
                "acl": {"grants": []},
                "bucket_policy": {"statements": [statement]},
                "encryption": {"enabled": True},
                "versioning": {"status": "Enabled"},
            }
        ]
    }


class StorageAnalyzerTests(unittest.TestCase):
    def test_sample_environment_detects_expected_storage_risks(self):
        environment = load_environment(SAMPLE_FILE)

        findings = analyze_environment(environment)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertEqual(9, len(findings))
        self.assertIn("STO-001", rule_ids)
        self.assertIn("STO-002", rule_ids)
        self.assertIn("STO-003", rule_ids)
        self.assertIn("STO-004", rule_ids)
        self.assertIn("STO-005", rule_ids)
        self.assertIn("STO-006", rule_ids)
        self.assertTrue(all(finding.module == "storage" for finding in findings))
        self.assertTrue(all(finding.category == "data-exposure" for finding in findings))
        self.assertTrue(all(finding.references for finding in findings))

    def test_private_encrypted_versioned_bucket_has_no_findings(self):
        environment = {
            "buckets": [
                {
                    "name": "private-secure-bucket",
                    "public_access_block": {
                        "block_public_acls": True,
                        "ignore_public_acls": True,
                        "block_public_policy": True,
                        "restrict_public_buckets": True,
                    },
                    "acl": {
                        "grants": [
                            {
                                "grantee": "AccountOwner",
                                "permission": "FULL_CONTROL",
                            }
                        ]
                    },
                    "bucket_policy": {
                        "statements": []
                    },
                    "encryption": {
                        "enabled": True,
                        "algorithm": "aws:kms",
                    },
                    "versioning": {
                        "status": "Enabled",
                    },
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertEqual([], findings)

    def test_public_principal_dict_is_detected(self):
        environment = {
            "buckets": [
                {
                    "name": "public-policy-bucket",
                    "public_access_block": {
                        "block_public_acls": True,
                        "ignore_public_acls": True,
                        "block_public_policy": True,
                        "restrict_public_buckets": False,
                    },
                    "acl": {"grants": []},
                    "bucket_policy": {
                        "statements": [
                            {
                                "effect": "Allow",
                                "principal": {"AWS": "*"},
                                "action": "s3:GetObject",
                                "resource": "arn:aws:s3:::public-policy-bucket/*",
                            }
                        ]
                    },
                    "encryption": {"enabled": True},
                    "versioning": {"status": "Enabled"},
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertIn("STO-003", [finding.rule_id for finding in findings])

    def test_public_principal_list_is_detected(self):
        environment = {
            "buckets": [
                {
                    "name": "public-list-principal",
                    "public_access_block": {
                        "block_public_acls": True,
                        "ignore_public_acls": True,
                        "block_public_policy": True,
                        "restrict_public_buckets": False,
                    },
                    "acl": {"grants": []},
                    "bucket_policy": {
                        "statements": [
                            {
                                "effect": "Allow",
                                "principal": {"AWS": ["*"]},
                                "action": "s3:GetObject",
                                "resource": "arn:aws:s3:::public-list-principal/*",
                            }
                        ]
                    },
                    "encryption": {"enabled": True},
                    "versioning": {"status": "Enabled"},
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertIn("STO-003", [finding.rule_id for finding in findings])

    def test_effective_public_access_block_suppresses_inactive_acl_and_policy_exposure(self):
        environment = {
            "buckets": [
                {
                    "name": "protected-public-artifacts",
                    "public_access_block": {
                        "block_public_acls": True,
                        "ignore_public_acls": True,
                        "block_public_policy": True,
                        "restrict_public_buckets": True,
                    },
                    "acl": {
                        "grants": [
                            {
                                "grantee": "AllUsers",
                                "permission": "READ",
                            }
                        ]
                    },
                    "bucket_policy": {
                        "statements": [
                            {
                                "effect": "Allow",
                                "principal": "*",
                                "action": "s3:GetObject",
                                "resource": "arn:aws:s3:::protected-public-artifacts/*",
                            }
                        ]
                    },
                    "encryption": {"enabled": True},
                    "versioning": {"status": "Enabled"},
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertEqual([], findings)

    def test_missing_explicit_encryption_is_low_severity_posture_gap(self):
        environment = {
            "buckets": [
                {
                    "name": "baseline-encrypted",
                    "public_access_block": {
                        "block_public_acls": True,
                        "ignore_public_acls": True,
                        "block_public_policy": True,
                        "restrict_public_buckets": True,
                    },
                    "acl": {"grants": []},
                    "bucket_policy": {"statements": []},
                    "encryption": {"enabled": False},
                    "versioning": {"status": "Enabled"},
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertEqual(["STO-004"], [finding.rule_id for finding in findings])
        self.assertEqual("low", findings[0].severity)
        self.assertIn("explicit", findings[0].title.lower())

    def test_fixed_value_policy_conditions_make_wildcard_principal_non_public(self):
        conditions = (
            {"StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4e5"}},
            {"StringEqualsIgnoreCase": {"aws:SourceAccount": "111122223333"}},
            {"StringLike": {"aws:SourceVpc": "vpc-0123456789abcdef0"}},
            {
                "ArnLike": {
                    "s3:DataAccessPointArn": (
                        "arn:aws:s3:ap-southeast-2:111122223333:accesspoint/*"
                    )
                }
            },
            {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            {"IpAddress": {"aws:SourceIp": "2001:db8::/32"}},
            {
                "ForAllValues:StringEquals": {
                    "aws:SourceAccount": ["111122223333", "999988887777"],
                },
                "Null": {"aws:SourceAccount": "false"},
            },
        )

        for condition in conditions:
            with self.subTest(condition=condition):
                findings = analyze_environment(_policy_environment(condition))

                self.assertNotIn("STO-003", [finding.rule_id for finding in findings])

    def test_non_fixed_or_overly_broad_policy_conditions_remain_public(self):
        conditions = (
            {"StringLike": {"aws:SourceVpc": "vpc-*"}},
            {"StringEqualsIfExists": {"aws:SourceAccount": "111122223333"}},
            {"StringNotEquals": {"aws:SourceAccount": "999988887777"}},
            {"StringEquals": {"aws:SourceArn": "${aws:PrincipalArn}"}},
            {"IpAddress": {"aws:SourceIp": "0.0.0.0/1"}},
            {"IpAddress": {"aws:SourceIp": "::/0"}},
            {"IpAddress": {"aws:SourceIp": "not-a-cidr"}},
            {
                "StringEquals": {
                    "aws:SourceAccount": ["111122223333", "*"],
                }
            },
            {
                "ArnLike": {
                    "s3:DataAccessPointArn": (
                        "arn:aws:s3:ap-southeast-2:*:accesspoint/*"
                    )
                }
            },
            {
                "ForAllValues:StringEquals": {
                    "aws:SourceAccount": ["111122223333"],
                }
            },
        )

        for condition in conditions:
            with self.subTest(condition=condition):
                findings = analyze_environment(_policy_environment(condition))
                policy_findings = [
                    finding for finding in findings if finding.rule_id == "STO-003"
                ]

                self.assertEqual(1, len(policy_findings))
                self.assertTrue(policy_findings[0].metadata["condition_keys"])
                self.assertIn(
                    json.dumps(condition, sort_keys=True),
                    policy_findings[0].evidence,
                )

    def test_allow_not_principal_is_treated_as_broad_access(self):
        findings = analyze_environment(_policy_environment(None, use_not_principal=True))
        policy_finding = next(
            finding for finding in findings if finding.rule_id == "STO-003"
        )

        self.assertEqual("NotPrincipal", policy_finding.metadata["principal_element"])
        self.assertIn("NotPrincipal", policy_finding.evidence)

    def test_bucket_owner_enforced_suppresses_acl_exposure(self):
        environment = {
            "buckets": [
                {
                    "name": "acl-disabled",
                    "object_ownership": "BucketOwnerEnforced",
                    "public_access_block": {
                        "block_public_acls": True,
                        "ignore_public_acls": False,
                        "block_public_policy": True,
                        "restrict_public_buckets": True,
                    },
                    "acl": {
                        "grants": [
                            {"grantee": "AllUsers", "permission": "READ"},
                        ]
                    },
                    "bucket_policy": {"statements": []},
                    "encryption": {"enabled": True},
                    "versioning": {"status": "Enabled"},
                }
            ]
        }

        findings = analyze_environment(environment)

        self.assertNotIn("STO-002", [finding.rule_id for finding in findings])
        self.assertNotIn("STO-006", [finding.rule_id for finding in findings])

    def test_acl_enabled_ownership_modes_are_reported_once(self):
        for ownership in ("BucketOwnerPreferred", "ObjectWriter"):
            with self.subTest(ownership=ownership):
                environment = {
                    "buckets": [
                        {
                            "name": "acl-enabled",
                            "object_ownership": ownership,
                            "public_access_block": {
                                "block_public_acls": True,
                                "ignore_public_acls": True,
                                "block_public_policy": True,
                                "restrict_public_buckets": True,
                            },
                            "acl": {"grants": []},
                            "bucket_policy": {"statements": []},
                            "encryption": {"enabled": True},
                            "versioning": {"status": "Enabled"},
                        }
                    ]
                }

                findings = analyze_environment(environment)
                ownership_findings = [
                    finding for finding in findings if finding.rule_id == "STO-006"
                ]

                self.assertEqual(1, len(ownership_findings))
                self.assertEqual(
                    ownership,
                    ownership_findings[0].metadata["object_ownership"],
                )

    def test_findings_export_writes_shared_schema(self):
        environment = load_environment(SAMPLE_FILE)
        findings = analyze_environment(environment)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "storage_findings.json"
            write_findings(output_path, findings)
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual("1.0", payload["schema_version"])
        self.assertEqual(len(findings), payload["finding_count"])
        self.assertEqual(findings_to_dicts(findings), payload["findings"])


if __name__ == "__main__":
    unittest.main()
