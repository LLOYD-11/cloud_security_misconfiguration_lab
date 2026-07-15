import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from cloud_findings import write_findings
from iam_analyzer.analyzer import analyze_environment, load_environment

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_SAMPLE_PAIRS = (
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
