import copy
import gzip
import hashlib
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from cloud_analysis import write_analysis_summary
from cloud_findings import write_findings
from cloud_incidents import write_incidents
from cloud_inputs import validate_simplified_environment
from cloud_remediation import build_remediation_plan, write_remediation_plan
from cloud_security_lab.analysis import build_analysis_summary
from cloud_security_lab.normalizers.cloudtrail import load_aws_cloudtrail_environment
from cloud_security_lab.normalizers.ec2 import load_aws_ec2_environment
from cloud_security_lab.normalizers.iam import load_aws_iam_environment
from cloud_security_lab.normalizers.network_context import (
    apply_network_reachability_context,
    load_network_reachability_context,
)
from cloud_security_lab.normalizers.s3 import load_aws_s3_environment
from cloud_timeline import build_attack_timeline, write_attack_timeline
from cloudtrail_detector.detector import analyze_activity as analyze_cloudtrail_activity
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
    (
        "aws-fixture-manifest-v1.0.schema.json",
        "sample_data/aws/fixture-manifest-v1.0.json",
    ),
    (
        "benchmark-manifest-v1.0.schema.json",
        "cloud_benchmarks/benchmark-manifest-v1.0.json",
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

    def test_iam_contract_rejects_mutually_exclusive_statement_elements(self):
        schema = _load_json(
            PROJECT_ROOT / "schemas/iam-environment-v1.0.schema.json"
        )
        validator = Draft202012Validator(schema)
        conflicts = (
            {"action": "*", "not_action": "iam:*"},
            {"action": "*", "resource": "*", "not_resource": "example"},
            {
                "action": "sts:AssumeRole",
                "principal": "*",
                "not_principal": {"AWS": "111122223333"},
            },
        )

        for fields in conflicts:
            environment = {
                "account_id": "111122223333",
                "users": [],
                "roles": [
                    {
                        "name": "ambiguous-role",
                        "trust_policy": {
                            "statements": [{"effect": "Allow", **fields}]
                        },
                        "attached_policies": [],
                    }
                ],
            }
            with self.subTest(fields=tuple(fields)):
                self.assertTrue(list(validator.iter_errors(environment)))

    def test_aws_fixture_manifest_is_complete_and_integrity_checked(self):
        manifest = _load_json(
            PROJECT_ROOT / "sample_data/aws/fixture-manifest-v1.0.json"
        )
        fixtures = manifest["fixtures"]
        declared_paths = [item["path"] for item in fixtures]
        discovered_paths = sorted(
            str(path.relative_to(PROJECT_ROOT))
            for path in (PROJECT_ROOT / "sample_data/aws").rglob("*")
            if path.is_file() and path.name != "fixture-manifest-v1.0.json"
        )

        self.assertEqual(sorted(declared_paths), discovered_paths)
        self.assertEqual(len(declared_paths), len(set(declared_paths)))
        for fixture in fixtures:
            with self.subTest(path=fixture["path"]):
                fixture_path = PROJECT_ROOT / fixture["path"]
                contract_path = PROJECT_ROOT / fixture["contract"]
                digest = hashlib.sha256(fixture_path.read_bytes()).hexdigest()

                self.assertTrue(contract_path.is_file())
                self.assertEqual(fixture["sha256"], digest)
                self.assertLessEqual(
                    fixture["observed_from"],
                    fixture["observed_to"],
                )

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
        validate_simplified_environment("storage", result.environment)

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
        validate_simplified_environment("network", result.environment)
        validate_simplified_environment("network", enriched)

    def test_normalized_native_iam_environment_matches_iam_contract(self):
        schema = _load_json(PROJECT_ROOT / "schemas/iam-environment-v1.0.schema.json")
        result = load_aws_iam_environment(
            PROJECT_ROOT / "sample_data/aws/iam/account_authorization_details.json",
            PROJECT_ROOT / "sample_data/aws/iam/credential_report.csv",
            as_of=date(2026, 6, 30),
        )

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result.environment)
        validate_simplified_environment("iam", result.environment)

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
        validate_simplified_environment("cloudtrail", result.environment)

    def test_generated_findings_match_shared_contract(self):
        schema = _load_json(PROJECT_ROOT / "schemas/findings-v2.0.schema.json")
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

    def test_builtin_rule_catalog_matches_versioned_contract(self):
        schema = _load_json(
            PROJECT_ROOT / "schemas/rule-catalog-v1.0.schema.json"
        )
        catalog = _load_json(PROJECT_ROOT / "cloud_rules/rules-v1.0.json")

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).validate(catalog)

    def test_generated_incidents_match_shared_contract(self):
        schema = _load_json(PROJECT_ROOT / "schemas/incidents-v1.0.schema.json")
        environment = _load_json(
            PROJECT_ROOT / "sample_data/cloudtrail/sample_cloudtrail_events.json"
        )
        result = analyze_cloudtrail_activity(environment)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "incidents.json"
            write_incidents(path, result.incidents)
            payload = _load_json(path)

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).validate(payload)

    def test_generated_remediation_plan_matches_shared_contract(self):
        schema = _load_json(
            PROJECT_ROOT / "schemas/remediation-plan-v1.0.schema.json"
        )
        environment = _load_json(
            PROJECT_ROOT / "sample_data/cloudtrail/sample_cloudtrail_events.json"
        )
        result = analyze_cloudtrail_activity(environment)
        plan = build_remediation_plan(result.findings, result.incidents)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "remediation.json"
            write_remediation_plan(path, plan)
            payload = _load_json(path)

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).validate(payload)

    def test_generated_attack_timeline_matches_shared_contract(self):
        schema = _load_json(
            PROJECT_ROOT / "schemas/attack-timeline-v1.0.schema.json"
        )
        environment = _load_json(
            PROJECT_ROOT / "sample_data/cloudtrail/sample_cloudtrail_events.json"
        )
        result = analyze_cloudtrail_activity(environment)
        timeline = build_attack_timeline(result.findings, result.incidents)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "timeline.json"
            write_attack_timeline(path, timeline)
            payload = _load_json(path)

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).validate(payload)

        non_utc = copy.deepcopy(payload)
        non_utc["entries"][0]["first_seen"] = "2026-06-30T11:00:00+10:00"
        validator = Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )
        self.assertTrue(list(validator.iter_errors(non_utc)))

    def test_generated_analysis_summary_matches_shared_contract(self):
        schema = _load_json(
            PROJECT_ROOT / "schemas/analysis-summary-v1.0.schema.json"
        )
        environment = _load_json(
            PROJECT_ROOT / "sample_data/network/sample_network_environment.json"
        )
        summary = build_analysis_summary(
            module="network",
            environment=environment,
            input_format="simplified",
            input_file_count=1,
            finding_count=10,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "analysis-summary.json"
            write_analysis_summary(path, summary)
            payload = _load_json(path)

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(payload)


if __name__ == "__main__":
    unittest.main()
