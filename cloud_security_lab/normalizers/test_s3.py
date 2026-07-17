import copy
import json
import tempfile
import unittest
from pathlib import Path

from cloud_security_lab.normalizers.s3 import (
    load_aws_s3_environment,
    normalize_aws_s3_environment,
)
from storage_analyzer.analyzer import analyze_environment

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PATH = PROJECT_ROOT / "sample_data/aws/s3/s3_security_evidence_bundle.json"


def _bundle():
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


def _all_public_access_block(value):
    return {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": value,
            "IgnorePublicAcls": value,
            "BlockPublicPolicy": value,
            "RestrictPublicBuckets": value,
        }
    }


class NativeS3NormalizerTests(unittest.TestCase):
    def test_native_sample_normalizes_real_responses_and_detects_expected_risks(self):
        result = load_aws_s3_environment(SAMPLE_PATH)
        findings = analyze_environment(result.environment)

        self.assertEqual((), result.warnings)
        self.assertEqual("111122223333", result.environment["account_id"])
        self.assertEqual(7, len(findings))
        self.assertEqual(
            [
                "STO-002",
                "STO-003",
                "STO-001",
                "STO-005",
                "STO-005",
                "STO-006",
                "STO-006",
            ],
            [finding.rule_id for finding in findings],
        )
        self.assertTrue(
            all(bucket["encryption"]["enabled"] for bucket in result.environment["buckets"])
        )
        public_bucket = result.environment["buckets"][0]
        self.assertEqual(
            [
                "AccountOwner",
                "http://acs.amazonaws.com/groups/global/AllUsers",
            ],
            [grant["grantee"] for grant in public_bucket["acl"]["grants"]],
        )
        self.assertEqual(
            "PublicRead",
            public_bucket["bucket_policy"]["statements"][0]["sid"],
        )
        self.assertEqual("ObjectWriter", public_bucket["object_ownership"])
        self.assertEqual(
            {"IpAddress": {"aws:SourceIp": "0.0.0.0/1"}},
            public_bucket["bucket_policy"]["statements"][0]["condition"],
        )
        self.assertEqual(
            "BucketOwnerEnforced",
            result.environment["buckets"][1]["object_ownership"],
        )
        self.assertEqual(
            "arn:aws:kms:ap-southeast-2:111122223333:key/"
            "00000000-1111-2222-3333-444444444444",
            result.environment["buckets"][1]["encryption"]["key_id"],
        )
        self.assertEqual("Disabled", result.environment["buckets"][2]["versioning"]["status"])

    def test_account_public_access_block_is_combined_with_bucket_configuration(self):
        bundle = _bundle()
        bundle["AccountPublicAccessBlock"] = _all_public_access_block(True)
        bundle["BucketEvidence"][0]["GetPublicAccessBlock"] = {
            "Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}
        }

        result = normalize_aws_s3_environment(bundle)
        public_bucket = result.environment["buckets"][0]
        public_findings = [
            finding
            for finding in analyze_environment(result.environment)
            if finding.resource_id == "public-customer-exports"
        ]

        self.assertTrue(all(public_bucket["public_access_block"].values()))
        self.assertNotIn("STO-001", [finding.rule_id for finding in public_findings])

    def test_missing_bucket_policy_becomes_an_empty_statement_list(self):
        result = load_aws_s3_environment(SAMPLE_PATH)

        self.assertEqual(
            [],
            result.environment["buckets"][2]["bucket_policy"]["statements"],
        )

    def test_policy_object_and_single_statement_are_supported(self):
        bundle = _bundle()
        bundle["BucketEvidence"][0]["GetBucketPolicy"]["Policy"] = {
            "Statement": {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-customer-exports/*",
            }
        }

        result = normalize_aws_s3_environment(bundle)

        self.assertEqual(
            "Allow",
            result.environment["buckets"][0]["bucket_policy"]["statements"][0][
                "effect"
            ],
        )

    def test_negative_policy_elements_and_conditions_are_preserved(self):
        bundle = _bundle()
        bundle["BucketEvidence"][0]["GetBucketPolicy"]["Policy"] = {
            "Statement": {
                "Sid": "BroadExceptOwner",
                "Effect": "Allow",
                "NotPrincipal": {
                    "AWS": "arn:aws:iam::111122223333:root",
                },
                "NotAction": "s3:DeleteObject",
                "NotResource": "arn:aws:s3:::public-customer-exports/private/*",
                "Condition": {
                    "StringLike": {"aws:SourceVpc": "vpc-*"},
                },
            }
        }

        result = normalize_aws_s3_environment(bundle)
        statement = result.environment["buckets"][0]["bucket_policy"]["statements"][0]
        findings = analyze_environment(result.environment)

        self.assertEqual(
            {
                "AWS": "arn:aws:iam::111122223333:root",
            },
            statement["not_principal"],
        )
        self.assertEqual("s3:DeleteObject", statement["not_action"])
        policy_finding = next(
            finding.evidence for finding in findings if finding.rule_id == "STO-003"
        )
        self.assertIn("NotPrincipal", policy_finding)

    def test_default_encryption_can_coexist_with_an_additional_rule(self):
        bundle = _bundle()
        rules = bundle["BucketEvidence"][0]["GetBucketEncryption"][
            "ServerSideEncryptionConfiguration"
        ]["Rules"]
        rules.insert(0, {"BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]}})

        result = normalize_aws_s3_environment(bundle)

        self.assertEqual((), result.warnings)
        self.assertEqual(
            "AES256",
            result.environment["buckets"][0]["encryption"]["algorithm"],
        )

    def test_blocked_encryption_only_response_uses_the_s3_baseline(self):
        for encryption_type in ("NONE", ["SSE-C"]):
            with self.subTest(encryption_type=encryption_type):
                bundle = _bundle()
                bundle["BucketEvidence"][0]["GetBucketEncryption"][
                    "ServerSideEncryptionConfiguration"
                ]["Rules"] = [
                    {"BlockedEncryptionTypes": {"EncryptionType": encryption_type}}
                ]

                result = normalize_aws_s3_environment(bundle)

                self.assertEqual(
                    {"enabled": True, "algorithm": "AES256"},
                    result.environment["buckets"][0]["encryption"],
                )
                self.assertIn("S3 SSE-S3 baseline was used", result.warnings[0])

    def test_multiple_default_encryption_rules_are_rejected(self):
        bundle = _bundle()
        rules = bundle["BucketEvidence"][0]["GetBucketEncryption"][
            "ServerSideEncryptionConfiguration"
        ]["Rules"]
        rules.append(copy.deepcopy(rules[0]))

        with self.assertRaisesRegex(ValueError, "multiple default encryption rules"):
            normalize_aws_s3_environment(bundle)

    def test_every_blocked_encryption_rule_is_validated(self):
        bundle = _bundle()
        bundle["BucketEvidence"][0]["GetBucketEncryption"][
            "ServerSideEncryptionConfiguration"
        ]["Rules"] = [
            {"BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]}},
            {"BlockedEncryptionTypes": {"EncryptionType": []}},
        ]

        with self.assertRaisesRegex(ValueError, "non-empty list of strings"):
            normalize_aws_s3_environment(bundle)

    def test_paginated_bucket_lists_are_rejected(self):
        for pagination_key in ("ContinuationToken", "NextToken"):
            with self.subTest(pagination_key=pagination_key):
                bundle = _bundle()
                bundle["ListBuckets"][pagination_key] = "next-page"

                with self.assertRaisesRegex(ValueError, "collect all pages"):
                    normalize_aws_s3_environment(bundle)

    def test_prefix_filtered_bucket_list_is_rejected(self):
        bundle = _bundle()
        bundle["ListBuckets"]["Prefix"] = "internal-"

        with self.assertRaisesRegex(ValueError, "collect the full bucket inventory"):
            normalize_aws_s3_environment(bundle)

    def test_bucket_evidence_must_exactly_cover_listed_buckets(self):
        missing_bundle = _bundle()
        missing_bundle["BucketEvidence"].pop()
        with self.assertRaisesRegex(ValueError, "missing listed bucket"):
            normalize_aws_s3_environment(missing_bundle)

        extra_bundle = _bundle()
        extra = copy.deepcopy(extra_bundle["BucketEvidence"][0])
        extra["BucketName"] = "unlisted-bucket"
        extra_bundle["BucketEvidence"].append(extra)
        with self.assertRaisesRegex(ValueError, "unlisted bucket"):
            normalize_aws_s3_environment(extra_bundle)

    def test_duplicate_bucket_names_are_rejected(self):
        list_duplicate = _bundle()
        list_duplicate["ListBuckets"]["Buckets"].append(
            copy.deepcopy(list_duplicate["ListBuckets"]["Buckets"][0])
        )
        with self.assertRaisesRegex(ValueError, "ListBuckets contains duplicate"):
            normalize_aws_s3_environment(list_duplicate)

        evidence_duplicate = _bundle()
        evidence_duplicate["BucketEvidence"].append(
            copy.deepcopy(evidence_duplicate["BucketEvidence"][0])
        )
        with self.assertRaisesRegex(ValueError, "BucketEvidence contains duplicate"):
            normalize_aws_s3_environment(evidence_duplicate)

    def test_unexpected_collection_errors_are_not_treated_as_missing_configuration(self):
        cases = (
            ("AccountPublicAccessBlock", None),
            ("GetPublicAccessBlock", 0),
            ("GetBucketOwnershipControls", 0),
            ("GetBucketPolicy", 0),
            ("GetBucketAcl", 0),
            ("GetBucketEncryption", 0),
            ("GetBucketVersioning", 0),
        )
        for field, bucket_index in cases:
            with self.subTest(field=field):
                bundle = _bundle()
                target = (
                    bundle
                    if bucket_index is None
                    else bundle["BucketEvidence"][bucket_index]
                )
                target[field] = {"Error": {"Code": "AccessDenied"}}
                with self.assertRaisesRegex(ValueError, "AWS error AccessDenied"):
                    normalize_aws_s3_environment(bundle)

    def test_missing_ownership_controls_use_legacy_object_writer_behavior(self):
        bundle = _bundle()
        bundle["BucketEvidence"][0]["GetBucketOwnershipControls"] = {
            "Error": {"Code": "OwnershipControlsNotFoundError"}
        }

        result = normalize_aws_s3_environment(bundle)

        self.assertEqual(
            "ObjectWriter",
            result.environment["buckets"][0]["object_ownership"],
        )
        self.assertIn("legacy ACL-enabled ObjectWriter", result.warnings[0])

    def test_ownership_control_shape_and_value_are_validated(self):
        cases = (
            ({"OwnershipControls": {"Rules": []}}, "exactly one rule"),
            (
                {
                    "OwnershipControls": {
                        "Rules": [
                            {"ObjectOwnership": "ObjectWriter"},
                            {"ObjectOwnership": "BucketOwnerEnforced"},
                        ]
                    }
                },
                "exactly one rule",
            ),
            (
                {
                    "OwnershipControls": {
                        "Rules": [{"ObjectOwnership": "Unknown"}]
                    }
                },
                "must be BucketOwnerEnforced",
            ),
        )
        for ownership_controls, message in cases:
            with self.subTest(message=message):
                bundle = _bundle()
                bundle["BucketEvidence"][0]["GetBucketOwnershipControls"] = (
                    ownership_controls
                )

                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_s3_environment(bundle)

        missing_bundle = _bundle()
        del missing_bundle["BucketEvidence"][0]["GetBucketOwnershipControls"]
        with self.assertRaisesRegex(ValueError, "GetBucketOwnershipControls must be an object"):
            normalize_aws_s3_environment(missing_bundle)

    def test_malformed_public_access_block_is_rejected(self):
        bundle = _bundle()
        bundle["BucketEvidence"][0]["GetPublicAccessBlock"][
            "PublicAccessBlockConfiguration"
        ]["BlockPublicAcls"] = "false"

        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            normalize_aws_s3_environment(bundle)

    def test_malformed_policy_is_rejected(self):
        cases = (
            ("not-json", "not valid JSON"),
            ([], "must be a JSON object"),
            ({"Statement": "Allow"}, "Statement must be"),
        )
        for policy, message in cases:
            with self.subTest(message=message):
                bundle = _bundle()
                bundle["BucketEvidence"][0]["GetBucketPolicy"]["Policy"] = policy
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_s3_environment(bundle)

    def test_malformed_acl_is_rejected(self):
        cases = (
            ("Owner", {}, "missing a non-empty ID"),
            ("Grants", {}, "must be a list of objects"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                bundle = _bundle()
                bundle["BucketEvidence"][0]["GetBucketAcl"][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_s3_environment(bundle)

        bundle = _bundle()
        bundle["BucketEvidence"][0]["GetBucketAcl"]["Grants"][0]["Grantee"] = {
            "Type": "CanonicalUser"
        }
        with self.assertRaisesRegex(ValueError, "has no URI"):
            normalize_aws_s3_environment(bundle)

    def test_malformed_encryption_is_rejected(self):
        cases = (
            ([], "must not be empty"),
            ([{}], "neither a default nor blocked encryption rule"),
            (
                [{"ApplyServerSideEncryptionByDefault": []}],
                "ApplyServerSideEncryptionByDefault",
            ),
            (
                [{"BlockedEncryptionTypes": {"EncryptionType": ["unknown"]}}],
                "must contain SSE-C or NONE",
            ),
            (
                [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256", "KMSMasterKeyID": ""}}],
                "KMSMasterKeyID",
            ),
        )
        for rules, message in cases:
            with self.subTest(message=message):
                bundle = _bundle()
                bundle["BucketEvidence"][0]["GetBucketEncryption"][
                    "ServerSideEncryptionConfiguration"
                ]["Rules"] = rules
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_s3_environment(bundle)

    def test_invalid_versioning_status_is_rejected(self):
        bundle = _bundle()
        bundle["BucketEvidence"][0]["GetBucketVersioning"]["Status"] = "Disabled"

        with self.assertRaisesRegex(ValueError, "Enabled, Suspended, or absent"):
            normalize_aws_s3_environment(bundle)

    def test_bundle_header_is_validated(self):
        cases = (
            ("schema_version", "2.0", "schema_version"),
            ("account_id", "example", "12-digit"),
            ("ListBuckets", [], "must be an object"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                bundle = _bundle()
                bundle[field] = value
                with self.assertRaisesRegex(ValueError, message):
                    normalize_aws_s3_environment(bundle)

    def test_loader_rejects_non_object_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bundle.json"
            path.write_text("[]", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "must contain a JSON object"):
                load_aws_s3_environment(path)


if __name__ == "__main__":
    unittest.main()
