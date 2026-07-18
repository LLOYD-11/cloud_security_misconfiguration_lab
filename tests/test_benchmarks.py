import json
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker

from cloud_benchmarks.coverage_gate import evaluate_coverage, main as coverage_main
from cloud_benchmarks.manifest_builder import build_manifest, main as builder_main
from cloud_benchmarks.models import load_benchmark_manifest
from cloud_benchmarks.profiles import ANALYZERS, environment_for_profile
from cloud_benchmarks.runner import (
    execute_benchmarks,
    main as runner_main,
    run_functional_cases,
    run_scale_cases,
)
from cloud_rules import load_builtin_catalog

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_SCHEMAS = {
    "iam": "iam-environment-v1.0.schema.json",
    "storage": "storage-environment-v1.0.schema.json",
    "network": "network-environment-v1.0.schema.json",
    "cloudtrail": "cloudtrail-events-v1.0.schema.json",
}


def _load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


class BenchmarkContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = load_benchmark_manifest()
        cls.cases_by_id = {
            case["id"]: case for case in cls.manifest["cases"]
        }

    def test_manifest_matches_schema_and_declared_counts(self):
        schema = _load_json(
            PROJECT_ROOT / "schemas/benchmark-manifest-v1.0.schema.json"
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).validate(self.manifest)

        self.assertEqual(
            self.manifest["case_count"],
            len(self.manifest["cases"]),
        )
        self.assertEqual(
            self.manifest["scale_case_count"],
            len(self.manifest["scale_cases"]),
        )
        self.assertEqual(
            len(self.cases_by_id),
            len(self.manifest["cases"]),
        )
        scale_cases = self.manifest["scale_cases"]
        self.assertEqual(
            {
                f"{module}-{size}"
                for module in MODULE_SCHEMAS
                for size in ("small", "large")
            },
            {case["id"] for case in scale_cases},
        )
        self.assertEqual(len(scale_cases), len({case["id"] for case in scale_cases}))
        self.assertEqual(
            {
                "minimum_statement_coverage_percent": 90.0,
                "minimum_branch_coverage_percent": 85.0,
                "required_functional_pass_rate": 1.0,
                "required_malformed_rejection_rate": 1.0,
                "require_scale_determinism": True,
                "wall_clock_gate_enabled": False,
            },
            self.manifest["acceptance_budgets"],
        )
        for case in scale_cases:
            expected_memory = (
                16 * 1024 * 1024
                if case["size"] == "small"
                else 64 * 1024 * 1024
            )
            self.assertEqual(case["input_count"] // 10, case["expected_finding_count"])
            self.assertEqual(
                case["expected_finding_count"],
                sum(case["expected_rule_counts"].values()),
            )
            self.assertEqual(0.1, case["max_findings_per_input"])
            self.assertEqual(expected_memory, case["max_peak_memory_bytes"])
        self.assertEqual(self.manifest, build_manifest())

    def test_every_catalog_rule_has_all_four_case_classes(self):
        catalog = load_builtin_catalog()
        catalog_rules = {rule.rule_id: rule for rule in catalog.rules}
        coverage = {
            row["rule_id"]: row for row in self.manifest["rule_coverage"]
        }

        self.assertEqual(catalog_rules.keys(), coverage.keys())
        self.assertEqual(len(catalog_rules), len(self.manifest["rule_coverage"]))
        self.assertEqual(self.manifest["rule_count"], len(catalog_rules))
        self.assertEqual(
            Counter(
                {
                    "positive": 35,
                    "boundary": 35,
                    "negative": 4,
                    "malformed": 4,
                }
            ),
            Counter(case["classification"] for case in self.manifest["cases"]),
        )
        for rule_id, row in coverage.items():
            with self.subTest(rule_id=rule_id):
                self.assertEqual(catalog_rules[rule_id].module, row["module"])
                for classification in (
                    "positive",
                    "negative",
                    "boundary",
                    "malformed",
                ):
                    case = self.cases_by_id[row[f"{classification}_case"]]
                    self.assertEqual(classification, case["classification"])
                    self.assertEqual(row["module"], case["module"])
                    self.assertIn(rule_id, case["covers_rules"])

    def test_case_expectations_encode_positive_boundary_and_fail_closed_semantics(self):
        for case in self.manifest["cases"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["false_positive_rationale"].strip())
                self.assertTrue(case["unsupported_evidence"])
                classification = case["classification"]
                if classification == "positive":
                    expected_rules = {
                        item["rule_id"] for item in case["expected_findings"]
                    }
                    self.assertTrue(set(case["covers_rules"]).issubset(expected_rules))
                elif classification == "boundary":
                    expected_rules = {
                        item["rule_id"] for item in case["expected_findings"]
                    }
                    self.assertTrue(set(case["covers_rules"]).isdisjoint(expected_rules))
                elif classification == "negative":
                    self.assertEqual([], case["expected_findings"])
                else:
                    self.assertEqual("ValueError", case["expected_error"]["type"])
                    self.assertNotIn("expected_findings", case)

    def test_non_malformed_profiles_match_simplified_input_contracts(self):
        validators = {
            module: Draft202012Validator(
                _load_json(PROJECT_ROOT / "schemas" / schema_name),
                format_checker=FormatChecker(),
            )
            for module, schema_name in MODULE_SCHEMAS.items()
        }
        for case in self.manifest["cases"]:
            if case["classification"] == "malformed":
                continue
            with self.subTest(case=case["id"]):
                module, environment = environment_for_profile(case["profile"])
                self.assertEqual(case["module"], module)
                validators[module].validate(environment)

    def test_all_functional_cases_match_exact_golden_contract(self):
        results = run_functional_cases(self.manifest)

        self.assertEqual(78, len(results))
        self.assertTrue(all(result["passed"] for result in results))
        malformed_results = [
            result
            for result, case in zip(
                results,
                self.manifest["cases"],
                strict=True,
            )
            if case["classification"] == "malformed"
        ]
        self.assertEqual(4, len(malformed_results))
        self.assertTrue(all(result["passed"] for result in malformed_results))

    def test_small_scale_profiles_meet_deterministic_resource_budgets(self):
        small_manifest = {
            **self.manifest,
            "scale_cases": [
                case
                for case in self.manifest["scale_cases"]
                if case["size"] == "small"
            ],
        }

        results = run_scale_cases(small_manifest)

        self.assertEqual(4, len(results))
        self.assertTrue(all(result["passed"] for result in results))
        self.assertTrue(all(result["deterministic"] for result in results))
        self.assertTrue(
            all(result["finding_amplification"] == 0.1 for result in results)
        )

    def test_benchmark_results_match_versioned_contract(self):
        schema = _load_json(
            PROJECT_ROOT / "schemas/benchmark-results-v1.0.schema.json"
        )
        small_manifest = {
            **self.manifest,
            "scale_cases": [
                case
                for case in self.manifest["scale_cases"]
                if case["size"] == "small"
            ],
        }
        result = execute_benchmarks(small_manifest)

        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).validate(result)
        self.assertTrue(result["passed"])
        self.assertEqual(4, result["scale_case_count"])

    def test_separate_statement_and_branch_coverage_budgets(self):
        passing = {
            "totals": {
                "covered_lines": 900,
                "num_statements": 1000,
                "covered_branches": 850,
                "num_branches": 1000,
            }
        }
        statement, branch, failures = evaluate_coverage(
            passing,
            self.manifest,
        )
        self.assertEqual(90.0, statement)
        self.assertEqual(85.0, branch)
        self.assertEqual([], failures)

        failing = {
            "totals": {
                "covered_lines": 899,
                "num_statements": 1000,
                "covered_branches": 849,
                "num_branches": 1000,
            }
        }
        _, _, failures = evaluate_coverage(failing, self.manifest)
        self.assertEqual(2, len(failures))

        with self.assertRaisesRegex(
            ValueError,
            "statement denominator must be positive",
        ):
            evaluate_coverage(
                {
                    "totals": {
                        "covered_lines": 0,
                        "num_statements": 0,
                        "covered_branches": 1,
                        "num_branches": 1,
                    }
                },
                self.manifest,
            )


class BenchmarkFailureAndCliTests(unittest.TestCase):
    def setUp(self):
        self.manifest = load_benchmark_manifest()

    def test_manifest_loader_supports_paths_and_rejects_invalid_payloads(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "manifest.json"
            path.write_text(json.dumps(self.manifest), encoding="utf-8")
            self.assertEqual(self.manifest, load_benchmark_manifest(path))

            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must contain a JSON object"):
                load_benchmark_manifest(path)

            path.write_text('{"schema_version": "9.0"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsupported schema version"):
                load_benchmark_manifest(path)

            invalid = {
                **self.manifest,
                "case_count": 0,
                "cases": [],
            }
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "cases must be a non-empty"):
                load_benchmark_manifest(path)

            invalid = {**self.manifest, "scale_case_count": 7}
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "scale_case_count must equal"):
                load_benchmark_manifest(path)

            invalid = {**self.manifest, "rule_count": 34}
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "rule_count must equal"):
                load_benchmark_manifest(path)

            invalid = {**self.manifest, "acceptance_budgets": []}
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "acceptance_budgets"):
                load_benchmark_manifest(path)

    def test_manifest_builder_cli_writes_the_golden_snapshot(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "nested" / "benchmark.json"
            with redirect_stdout(StringIO()):
                return_code = builder_main(["--output", str(output)])

            self.assertEqual(0, return_code)
            self.assertEqual(self.manifest, _load_json(output))

    def test_benchmark_runner_cli_writes_functional_results(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "nested" / "results.json"
            with redirect_stdout(StringIO()):
                return_code = runner_main(
                    ["--skip-scale", "--output", str(output)]
                )
            result = _load_json(output)

            self.assertEqual(0, return_code)
            self.assertTrue(result["passed"])
            self.assertEqual(78, result["functional_passed_count"])
            self.assertEqual(4, result["malformed_rejected_count"])
            self.assertEqual(0, result["scale_case_count"])

    def test_coverage_gate_cli_uses_manifest_thresholds(self):
        passing = {
            "totals": {
                "covered_lines": 90,
                "num_statements": 100,
                "covered_branches": 85,
                "num_branches": 100,
            }
        }
        failing = {
            "totals": {
                "covered_lines": 89,
                "num_statements": 100,
                "covered_branches": 84,
                "num_branches": 100,
            }
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "coverage.json"
            with redirect_stdout(StringIO()):
                path.write_text(json.dumps(passing), encoding="utf-8")
                self.assertEqual(0, coverage_main([str(path)]))
                path.write_text(json.dumps(failing), encoding="utf-8")
                self.assertEqual(1, coverage_main([str(path)]))

    def test_runner_exposes_expectation_budget_and_determinism_failures(self):
        positive = next(
            case
            for case in self.manifest["cases"]
            if case["classification"] == "positive"
        )
        mismatch = {**positive, "expected_findings": []}
        mismatch_result = run_functional_cases({"cases": [mismatch]})[0]
        self.assertFalse(mismatch_result["passed"])
        self.assertIn("Expected", mismatch_result["message"])

        with patch(
            "cloud_benchmarks.runner.run_functional_profile",
            side_effect=RuntimeError("benchmark failure"),
        ):
            exception_result = run_functional_cases({"cases": [positive]})[0]
        self.assertFalse(exception_result["passed"])
        self.assertIn("Unexpected RuntimeError", exception_result["message"])

        malformed = next(
            case
            for case in self.manifest["cases"]
            if case["classification"] == "malformed"
        )
        with patch(
            "cloud_benchmarks.runner.run_functional_profile",
            return_value=[],
        ):
            accepted_result = run_functional_cases({"cases": [malformed]})[0]
        self.assertFalse(accepted_result["passed"])
        self.assertIn("unexpectedly accepted", accepted_result["message"])

        iam_small = next(
            case
            for case in self.manifest["scale_cases"]
            if case["id"] == "iam-small"
        )
        strict_case = {
            **iam_small,
            "expected_finding_count": 11,
            "max_findings_per_input": 0.09,
            "max_peak_memory_bytes": 1,
        }
        strict_result = run_scale_cases({"scale_cases": [strict_case]})[0]
        self.assertFalse(strict_result["passed"])
        self.assertIn("finding count", strict_result["message"])
        self.assertIn("finding amplification", strict_result["message"])
        self.assertIn("peak memory", strict_result["message"])

        original_analyzer = ANALYZERS["iam"]
        invocation_count = 0

        def alternating_analyzer(environment):
            nonlocal invocation_count
            invocation_count += 1
            findings = original_analyzer(environment)
            return findings if invocation_count == 1 else []

        with patch.dict(ANALYZERS, {"iam": alternating_analyzer}):
            nondeterministic = run_scale_cases({"scale_cases": [iam_small]})[0]
        self.assertFalse(nondeterministic["passed"])
        self.assertIn("different findings", nondeterministic["message"])


if __name__ == "__main__":
    unittest.main()
