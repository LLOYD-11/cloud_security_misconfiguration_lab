import copy
import gzip
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from cloud_findings import write_findings
from cloud_security_lab.normalizers.cloudtrail import load_aws_cloudtrail_environment
from cloud_security_lab.normalizers.ec2 import load_aws_ec2_environment
from cloud_security_lab.normalizers.iam import load_aws_iam_environment
from cloud_security_lab.normalizers.network_context import (
    apply_network_reachability_context,
    load_network_reachability_context,
)
from cloud_security_lab.normalizers.s3 import load_aws_s3_environment
from iam_analyzer.analyzer import analyze_environment, load_environment

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_SAMPLE_PAIRS = (
    (
        "aws-cloudtrail-records-v1.0.schema.json",
        "sample_data/aws/cloudtrail/111122223333_CloudTrail_20260630T0200Z_part1.json",
    ),
    (
        "aws-ec2-describe-security-groups-v1.0.schema.json",
        "sample_data/aws/ec2/describe_security_groups.json",
    ),
    (
        "aws-iam-authorization-details-v1.0.schema.json",
        "sample_data/aws/iam/account_authorization_details.json",
    ),
    (
        "aws-s3-evidence-bundle-v1.0.schema.json",
        "sample_data/aws/s3/s3_security_evidence_bundle.json",
    ),
    (
        "iam-environment-v1.0.schema.json",
        "sample_data/iam/sample_iam_environment.json",
    ),
    (
        "storage-environment-v1.0.schema.json",
        "sample_data/storage/sample_storage_environment.json",
    ),
    (
        "network-environment-v1.0.schema.json",
        "sample_data/network/sample_network_environment.json",
    ),
    (
        "network-reachability-context-v1.0.schema.json",
        "sample_data/aws/ec2/network_reachability_context.json",
    ),
    (
        "cloudtrail-events-v1.0.schema.json",
        "sample_data/cloudtrail/sample_cloudtrail_events.json",
    ),
)


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class DataContractTests(unittest.TestCase):
    def test_committed_samples_match_versioned_contracts(self):
        for schema_name, sample_name in SCHEMA_SAMPLE_PAIRS:
            with self.subTest(schema=schema_name):
                schema = _load_json(PROJECT_ROOT / "schemas" / schema_name)
                sample = _load_json(PROJECT_ROOT / sample_name)
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(
                    schema,
                    format_checker=FormatChecker(),
                ).validate(sample)

    def test_s3_contract_supports_blocked_encryption_rules_and_rejects_empty_rules(self):
        schema = _load_json(
            PROJECT_ROOT / "schemas/aws-s3-evidence-bundle-v1.0.schema.json"
        )
        sample = _load_json(
            PROJECT_ROOT / "sample_data/aws/s3/s3_security_evidence_bundle.json"
        )
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        rules = sample["BucketEvidence"][0]["GetBucketEncryption"][
            "ServerSideEncryptionConfiguration"
        ]["Rules"]

        for encryption_type in ("NONE", ["SSE-C"]):
            with self.subTest(encryption_type=encryption_type):
                candidate = copy.deepcopy(sample)
                candidate["BucketEvidence"][0]["GetBucketEncryption"][
                    "ServerSideEncryptionConfiguration"
                ]["Rules"] = [
                    {"BlockedEncryptionTypes": {"EncryptionType": encryption_type}}
                ]
                validator.validate(candidate)

        rules[:] = [{}]
        self.assertTrue(list(validator.iter_errors(sample)))

        missing_ownership = copy.deepcopy(sample)
        del missing_ownership["BucketEvidence"][0]["GetBucketOwnershipControls"]
        self.assertTrue(list(validator.iter_errors(missing_ownership)))

    def test_normalized_native_s3_environment_matches_storage_contract(self):
        schema = _load_json(PROJECT_ROOT / "schemas/storage-environment-v1.0.schema.json")
        result = load_aws_s3_environment(
            PROJECT_ROOT / "sample_data/aws/s3/s3_security_evidence_bundle.json"
        )

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result.environment)

    def test_normalized_native_ec2_environment_matches_network_contract(self):
        schema = _load_json(PROJECT_ROOT / "schemas/network-environment-v1.0.schema.json")
        result = load_aws_ec2_environment(
            PROJECT_ROOT / "sample_data/aws/ec2/describe_security_groups.json"
        )
        assessments = load_network_reachability_context(
            PROJECT_ROOT / "sample_data/aws/ec2/network_reachability_context.json"
        )
        enriched = apply_network_reachability_context(
            result.environment,
            assessments,
        ).environment

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result.environment)
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).validate(enriched)

    def test_normalized_native_iam_environment_matches_iam_contract(self):
        schema = _load_json(PROJECT_ROOT / "schemas/iam-environment-v1.0.schema.json")
        result = load_aws_iam_environment(
            PROJECT_ROOT / "sample_data/aws/iam/account_authorization_details.json",
            PROJECT_ROOT / "sample_data/aws/iam/credential_report.csv",
            as_of=date(2026, 6, 30),
        )

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result.environment)

    def test_gzip_cloudtrail_sample_and_normalized_environment_match_contracts(self):
        native_schema = _load_json(
            PROJECT_ROOT / "schemas/aws-cloudtrail-records-v1.0.schema.json"
        )
        gzip_path = (
            PROJECT_ROOT
            / "sample_data/aws/cloudtrail/"
            "111122223333_CloudTrail_20260630T0300Z_part2.json.gz"
        )
        with gzip.open(gzip_path, "rt", encoding="utf-8") as handle:
            gzip_payload = json.load(handle)

        validator = Draft202012Validator(
            native_schema,
            format_checker=FormatChecker(),
        )
        validator.validate(gzip_payload)

        normalized_schema = _load_json(
            PROJECT_ROOT / "schemas/cloudtrail-events-v1.0.schema.json"
        )
        result = load_aws_cloudtrail_environment(
            (
                PROJECT_ROOT
                / "sample_data/aws/cloudtrail/"
                "111122223333_CloudTrail_20260630T0200Z_part1.json",
                gzip_path,
            )
        )
        Draft202012Validator(
            normalized_schema,
            format_checker=FormatChecker(),
        ).validate(result.environment)

    def test_generated_findings_match_shared_contract(self):
        schema = _load_json(PROJECT_ROOT / "schemas/findings-v1.0.schema.json")
        environment = load_environment(
            PROJECT_ROOT / "sample_data/iam/sample_iam_environment.json"
        )
        findings = analyze_environment(environment)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "findings.json"
            write_findings(path, findings)
            payload = _load_json(path)

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(payload)


if __name__ == "__main__":
    unittest.main()
