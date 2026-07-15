import json
import tempfile
import unittest
from pathlib import Path

from cloud_findings import findings_to_dicts, write_findings
from storage_analyzer.analyzer import analyze_environment, load_environment


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FILE = PROJECT_ROOT / "sample_data" / "storage" / "sample_storage_environment.json"


class StorageAnalyzerTests(unittest.TestCase):
    def test_sample_environment_detects_expected_storage_risks(self):
        environment = load_environment(SAMPLE_FILE)

        findings = analyze_environment(environment)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertEqual(7, len(findings))
        self.assertIn("STO-001", rule_ids)
        self.assertIn("STO-002", rule_ids)
        self.assertIn("STO-003", rule_ids)
        self.assertIn("STO-004", rule_ids)
        self.assertIn("STO-005", rule_ids)
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
                        "restrict_public_buckets": True,
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

        self.assertEqual(["STO-003"], [finding.rule_id for finding in findings])

    def test_public_principal_list_is_detected(self):
        environment = {
            "buckets": [
                {
                    "name": "public-list-principal",
                    "public_access_block": {
                        "block_public_acls": True,
                        "ignore_public_acls": True,
                        "block_public_policy": True,
                        "restrict_public_buckets": True,
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

        self.assertEqual(["STO-003"], [finding.rule_id for finding in findings])

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
