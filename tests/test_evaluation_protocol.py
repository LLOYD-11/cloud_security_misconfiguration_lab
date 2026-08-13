import copy
import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = PROJECT_ROOT / "evaluation/protocol-v1.0.json"
SCHEMA_DIR = PROJECT_ROOT / "schemas"
EVALUATION_SCHEMAS = (
    "evaluation-protocol-v1.0.schema.json",
    "evaluation-corpus-manifest-v1.0.schema.json",
    "evaluation-baseline-overlap-v1.0.schema.json",
    "evaluation-baseline-outcomes-v1.0.schema.json",
    "evaluation-results-v1.0.schema.json",
)
MODULE_PREFIXES = {
    "iam": "IAM",
    "storage": "STO",
    "network": "NET",
    "cloudtrail": "CLD",
}


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(schema_name: str) -> Draft202012Validator:
    schema = _load_json(SCHEMA_DIR / schema_name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _artifact(path: str = "evaluation/protocol-v1.0.json") -> dict[str, object]:
    return {
        "path": path,
        "version": "1.0.0",
        "sha256": "a" * 64,
    }


def _metric_block(**identity: str) -> dict[str, object]:
    return {
        **identity,
        "confusion": {
            "true_positive": 1,
            "false_positive": 0,
            "false_negative": 0,
            "true_negative": 1,
        },
        "scores": {
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "specificity": 1.0,
        },
        "confidence_intervals": {
            "precision": {"lower": 0.2065, "upper": 1.0},
            "recall": {"lower": 0.2065, "upper": 1.0},
            "specificity": {"lower": 0.2065, "upper": 1.0},
        },
    }


def _corpus_sample() -> dict[str, object]:
    source = {
        "authority": "aws",
        "title": "AWS IAM policy elements",
        "url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html",
        "retrieved_on": "2026-08-12",
        "locator": "Policy element reference",
    }
    review = {
        "model": "procedural",
        "primary": {
            "reviewer_id": "primary-pass",
            "reviewed_on": "2026-08-13",
            "candidate_output_seen": False,
            "notes": "Labelled from retained evidence and AWS semantics.",
        },
        "verification": {
            "reviewer_id": "verification-pass",
            "reviewed_on": "2026-08-14",
            "candidate_output_seen": False,
            "notes": "Rechecked after a separate context reset.",
        },
        "resolution": "agreed",
    }
    return {
        "schema_version": "1.0",
        "corpus_id": "cloud-security-independent-corpus",
        "corpus_version": "1.0.0",
        "status": "frozen",
        "frozen_on": "2026-08-14",
        "description": "Independent holdout evidence for protocol contract tests.",
        "protocol": _artifact(),
        "candidate_revision": "6d71c99914a38b6e161bc9cf56407eb1757b8c9a",
        "independence": {
            "model": "procedural",
            "candidate_output_seen_during_authoring": False,
            "reused_project_fixture_count": 0,
            "reused_project_expectation_count": 0,
            "statement": "The example is independent from project benchmark fixtures.",
        },
        "case_count": 1,
        "file_count": 1,
        "cases": [
            {
                "id": "EVAL-IAM-001",
                "module": "iam",
                "classification": "positive",
                "title": "Full administrative policy",
                "description": "One independently authored IAM positive case.",
                "origins": ["independently-authored-synthetic"],
                "input_variants": [
                    {
                        "id": "simplified",
                        "input_form": "simplified",
                        "equivalence_group": None,
                        "files": [
                            {
                                "path": "evaluation/corpus-v1.0/iam/eval-iam-001.json",
                                "sha256": "b" * 64,
                                "size_bytes": 512,
                                "media_type": "application/json",
                                "contract": "schemas/iam-environment-v1.0.schema.json",
                            }
                        ],
                    }
                ],
                "assertions": [
                    {
                        "id": "AST-IAM-001-01",
                        "rule_id": "IAM-001",
                        "resource_type": "role",
                        "resource_id": "evaluation-admin",
                        "label": "positive",
                        "expected_severity": "critical",
                        "rationale": "Action and Resource are both full wildcards.",
                        "authoritative_references": [source],
                        "review": review,
                    }
                ],
                "provenance": {
                    "authored_on": "2026-08-13",
                    "source_references": [source],
                    "transformations": ["Authored directly in the simplified contract."],
                    "sanitization": ["Uses a fictional role and documentation account ID."],
                    "candidate_output_seen": False,
                },
                "baseline_eligible": True,
            }
        ],
        "integrity": {
            "algorithm": "sha256",
            "path_policy": "repository-relative-regular-files-no-symlinks",
            "inventory_policy": "every-corpus-file-declared-exactly-once",
        },
    }


def _overlap_sample() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "matrix_id": "cloud-security-baseline-overlap",
        "matrix_version": "1.0.0",
        "created_on": "2026-08-14",
        "protocol": _artifact(),
        "corpus": _artifact("evaluation/corpus-v1.0/manifest.json"),
        "rule_count": 1,
        "baseline_snapshots": [
            {
                "id": "prowler-aws",
                "version": "5.38.0",
                "commit_sha": "b21ddad32c6d9a98eb819f0ccadac8a6792c2837",
                "source_url": "https://github.com/prowler-cloud/prowler/tree/b21ddad32c6d9a98eb819f0ccadac8a6792c2837",
            },
            {
                "id": "sigma-core",
                "version": "r2026-07-01",
                "commit_sha": "552f3fee420ef232a8e5790c4fae591847e32347",
                "source_url": "https://github.com/SigmaHQ/sigma/tree/552f3fee420ef232a8e5790c4fae591847e32347",
                "release_asset_sha256": "45ccbd62cbf0d7ccca6f44eaa010f86bb24f082b5411c5e22c71907e7770ee46",
            },
        ],
        "comparison_policy": "Only equivalent predicates enter agreement metrics.",
        "rows": [
            {
                "lab_rule_id": "IAM-001",
                "module": "iam",
                "baseline_id": "prowler-aws",
                "baseline_check_ids": ["iam_policy_no_administrative_privileges"],
                "relationship": "exact",
                "predicate_direction": "equivalent",
                "comparison_eligible": True,
                "source_urls": [
                    "https://github.com/prowler-cloud/prowler/tree/b21ddad32c6d9a98eb819f0ccadac8a6792c2837"
                ],
                "rationale": "Both predicates reject full administrative wildcard grants.",
                "semantic_differences": [],
            }
        ],
    }


def _results_sample() -> dict[str, object]:
    assertion_result = {
        "case_id": "EVAL-IAM-001",
        "assertion_id": "AST-IAM-001-01",
        "module": "iam",
        "rule_id": "IAM-001",
        "resource_type": "role",
        "resource_id": "evaluation-admin",
        "truth_label": "positive",
        "prediction_count": 1,
        "duplicate_prediction_count": 0,
        "outcome": "true-positive",
        "expected_severity": "critical",
        "observed_severity": "critical",
        "severity_match": True,
        "message": "The candidate matched the frozen assertion.",
    }
    return {
        "schema_version": "1.0",
        "evaluation_id": "EVAL-RUN-2026-08-15-01",
        "evaluated_at": "2026-08-15T00:00:00Z",
        "protocol": _artifact(),
        "corpus": _artifact("evaluation/corpus-v1.0/manifest.json"),
        "overlap_matrix": _artifact("evaluation/baseline-overlap-v1.0.json"),
        "candidate": {
            "analyzer_revision": "6d71c99914a38b6e161bc9cf56407eb1757b8c9a",
            "package_version": "2.1.1",
            "rule_catalog_sha256": "5842caa836d7b8970ae9aef1261652cdd8f98a1c49598962de32be58c9e998a0",
        },
        "environment": {
            "python_version": "3.13.5",
            "platform": "Linux x86_64",
            "command": ["python", "-m", "cloud_evaluation.runner"],
            "clean_worktree": True,
        },
        "validity": {"valid": True, "issues": []},
        "counts": {
            "case_count": 1,
            "scored_assertion_count": 2,
            "excluded_assertion_count": 0,
            "unlabelled_prediction_count": 0,
            "duplicate_prediction_count": 0,
            "matched_positive_count": 1,
            "severity_match_count": 1,
        },
        "overall": _metric_block(),
        "per_module": [
            _metric_block(module=module)
            for module in ("iam", "storage", "network", "cloudtrail")
        ],
        "per_rule": [_metric_block(module="iam", rule_id="IAM-001")],
        "assertion_results": [assertion_result],
        "unexpected_predictions": [],
        "baseline_comparisons": [
            {
                "baseline_id": baseline_id,
                "eligible_decisions": 1,
                "agreements": 1,
                "disagreements": 0,
                "agreement_rate": 1.0,
                "disagreement_records": [],
            }
            for baseline_id in ("prowler-aws", "sigma-core")
        ],
        "ablations": [
            {
                "id": experiment_id,
                "eligible_cases": 1,
                "invariant_passed": True,
                "primary_decision_agreement": 1.0,
                "changed_severity_count": 0,
                "changed_incident_count": 0,
                "unexpected_change_count": 0,
                "notes": "The registered invariant held.",
            }
            for experiment_id in (
                "native-simplified-equivalence",
                "network-reachability-context",
                "cloudtrail-incident-correlation",
            )
        ],
        "acceptance": {
            "passed": True,
            "checks": [
                {
                    "id": "minimum-overall-micro-f1",
                    "observed": 1.0,
                    "operator": ">=",
                    "threshold": 0.9,
                    "passed": True,
                }
            ],
        },
    }


class EvaluationProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.protocol = _load_json(PROTOCOL_PATH)

    def test_all_evaluation_schemas_are_valid_draft_2020_12(self):
        for schema_name in EVALUATION_SCHEMAS:
            with self.subTest(schema=schema_name):
                _validator(schema_name)

    def test_frozen_protocol_matches_its_schema(self):
        _validator("evaluation-protocol-v1.0.schema.json").validate(self.protocol)

    def test_candidate_catalog_identity_and_module_inventory_are_frozen(self):
        catalog_path = PROJECT_ROOT / self.protocol["candidate"]["rule_catalog"]["path"]
        catalog = _load_json(catalog_path)
        catalog_digest = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
        declared_catalog = self.protocol["candidate"]["rule_catalog"]
        declared_modules = self.protocol["candidate"]["modules"]

        self.assertEqual(declared_catalog["sha256"], catalog_digest)
        self.assertEqual(declared_catalog["schema_version"], catalog["schema_version"])
        self.assertEqual(declared_catalog["rule_count"], len(catalog["rules"]))
        self.assertEqual(list(MODULE_PREFIXES), [item["id"] for item in declared_modules])

        rules_by_module = {
            module: [rule["rule_id"] for rule in catalog["rules"] if rule["module"] == module]
            for module in MODULE_PREFIXES
        }
        for module in declared_modules:
            with self.subTest(module=module["id"]):
                self.assertEqual(MODULE_PREFIXES[module["id"]], module["rule_prefix"])
                self.assertEqual(rules_by_module[module["id"]], module["rule_ids"])
                self.assertEqual(len(module["rule_ids"]), module["rule_count"])
                self.assertEqual(["native", "simplified"], module["input_forms"])

    def test_candidate_revision_predates_protocol_and_is_in_history(self):
        revision = self.protocol["candidate"]["analyzer_revision"]
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, "HEAD"],
            cwd=PROJECT_ROOT,
            check=False,
        )
        protocol_at_candidate = subprocess.run(
            ["git", "cat-file", "-e", f"{revision}:evaluation/protocol-v1.0.json"],
            cwd=PROJECT_ROOT,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        self.assertEqual(0, ancestor.returncode)
        self.assertNotEqual(0, protocol_at_candidate.returncode)

    def test_independence_labels_and_acceptance_rules_are_predeclared(self):
        controls = self.protocol["independence_controls"]
        corpus = self.protocol["corpus_design"]
        truth = self.protocol["ground_truth"]
        scoring = self.protocol["scoring"]

        self.assertFalse(controls["candidate_output_access_before_label_freeze"])
        self.assertFalse(controls["third_party_review_claimed"])
        self.assertEqual(
            ["positive", "negative", "ambiguous", "unsupported"],
            truth["labels"],
        )
        self.assertIn("cloud_benchmarks/", corpus["excluded_project_sources"])
        self.assertIn("sample_data/", corpus["excluded_project_sources"])
        self.assertEqual({"positive": 2, "negative": 2}, corpus["minimum_scored_assertions_per_rule"])
        self.assertEqual(0.9, scoring["acceptance_thresholds"]["minimum_overall_micro_f1"])
        self.assertEqual(0, scoring["acceptance_thresholds"]["maximum_unlabelled_predictions"])
        self.assertEqual(
            {"classification", "high_impact", "representation", "completeness"},
            scoring["acceptance_rationale"].keys(),
        )
        self.assertEqual(
            ["positive", "negative"],
            scoring["included_labels"],
        )
        self.assertEqual(
            ["RQ1", "RQ2", "RQ3", "RQ4"],
            [item["id"] for item in self.protocol["research_questions"]],
        )
        self.assertEqual(
            1,
            sum(item["primary"] for item in self.protocol["research_questions"]),
        )
        self.assertEqual(
            {
                "native-simplified-equivalence",
                "network-reachability-context",
                "cloudtrail-incident-correlation",
            },
            {item["id"] for item in self.protocol["experiments"]},
        )

    def test_external_baselines_use_fixed_releases_and_disjoint_scopes(self):
        baselines = {item["id"]: item for item in self.protocol["external_baselines"]}

        self.assertEqual({"prowler-aws", "sigma-core"}, baselines.keys())
        self.assertEqual("5.38.0", baselines["prowler-aws"]["version"])
        self.assertEqual(
            "b21ddad32c6d9a98eb819f0ccadac8a6792c2837",
            baselines["prowler-aws"]["commit_sha"],
        )
        self.assertEqual("r2026-07-01", baselines["sigma-core"]["version"])
        self.assertEqual(
            "552f3fee420ef232a8e5790c4fae591847e32347",
            baselines["sigma-core"]["commit_sha"],
        )
        self.assertEqual(
            "45ccbd62cbf0d7ccca6f44eaa010f86bb24f082b5411c5e22c71907e7770ee46",
            baselines["sigma-core"]["release_asset"]["sha256"],
        )
        baseline_modules = [set(item["modules"]) for item in baselines.values()]
        self.assertFalse(baseline_modules[0].intersection(baseline_modules[1]))
        self.assertEqual(set(MODULE_PREFIXES), set.union(*baseline_modules))
        self.assertTrue(
            all(item["ground_truth_role"] == "corroborating-only" for item in baselines.values())
        )

    def test_artifact_contracts_exist_and_have_matching_ids(self):
        for path_text in self.protocol["artifact_contracts"].values():
            with self.subTest(path=path_text):
                path = PROJECT_ROOT / path_text
                schema = _load_json(path)
                self.assertTrue(path.is_file())
                self.assertTrue(schema["$id"].endswith(f"/{path.name}"))

    def test_corpus_contract_enforces_blinding_paths_and_label_semantics(self):
        validator = _validator("evaluation-corpus-manifest-v1.0.schema.json")
        sample = _corpus_sample()
        validator.validate(sample)

        output_seen = copy.deepcopy(sample)
        output_seen["cases"][0]["provenance"]["candidate_output_seen"] = True
        self.assertTrue(list(validator.iter_errors(output_seen)))

        unsafe_path = copy.deepcopy(sample)
        unsafe_path["cases"][0]["input_variants"][0]["files"][0]["path"] = (
            "evaluation/corpus-v1.0/iam/../escape.json"
        )
        self.assertTrue(list(validator.iter_errors(unsafe_path)))

        no_aws_authority = copy.deepcopy(sample)
        no_aws_authority["cases"][0]["assertions"][0]["authoritative_references"][0][
            "authority"
        ] = "project-upstream"
        self.assertTrue(list(validator.iter_errors(no_aws_authority)))

        wrong_module = copy.deepcopy(sample)
        wrong_module["cases"][0]["assertions"][0]["rule_id"] = "STO-001"
        self.assertTrue(list(validator.iter_errors(wrong_module)))

        negative_with_severity = copy.deepcopy(sample)
        assertion = negative_with_severity["cases"][0]["assertions"][0]
        assertion["label"] = "negative"
        self.assertTrue(list(validator.iter_errors(negative_with_severity)))

        ambiguous_resolved = copy.deepcopy(sample)
        assertion = ambiguous_resolved["cases"][0]["assertions"][0]
        assertion["label"] = "ambiguous"
        assertion["expected_severity"] = None
        self.assertTrue(list(validator.iter_errors(ambiguous_resolved)))

        hardened_with_positive = copy.deepcopy(sample)
        hardened_with_positive["cases"][0]["classification"] = "hardened-negative"
        self.assertTrue(list(validator.iter_errors(hardened_with_positive)))

    def test_overlap_contract_excludes_partial_and_missing_counterparts(self):
        validator = _validator("evaluation-baseline-overlap-v1.0.schema.json")
        sample = _overlap_sample()
        validator.validate(sample)

        partial = copy.deepcopy(sample)
        row = partial["rows"][0]
        row["relationship"] = "partial"
        row["predicate_direction"] = "lab-broader"
        row["semantic_differences"] = ["The lab accepts a broader wildcard syntax."]
        self.assertTrue(list(validator.iter_errors(partial)))

        no_counterpart = copy.deepcopy(sample)
        row = no_counterpart["rows"][0]
        row["relationship"] = "none"
        row["predicate_direction"] = "no-counterpart"
        row["comparison_eligible"] = False
        row["baseline_check_ids"] = []
        row["semantic_differences"] = ["No released counterpart was identified."]
        validator.validate(no_counterpart)

    def test_results_contract_preserves_counts_exclusions_and_disagreements(self):
        validator = _validator("evaluation-results-v1.0.schema.json")
        sample = _results_sample()
        validator.validate(sample)

        invalid_ratio = copy.deepcopy(sample)
        invalid_ratio["overall"]["scores"]["precision"] = 1.01
        self.assertTrue(list(validator.iter_errors(invalid_ratio)))

        identified_overall = copy.deepcopy(sample)
        identified_overall["overall"]["module"] = "iam"
        self.assertTrue(list(validator.iter_errors(identified_overall)))

        rule_in_module_summary = copy.deepcopy(sample)
        rule_in_module_summary["per_module"][0]["rule_id"] = "IAM-001"
        self.assertTrue(list(validator.iter_errors(rule_in_module_summary)))

        uncounted_unexpected = copy.deepcopy(sample)
        uncounted_unexpected["unexpected_predictions"] = [
            {
                "case_id": "EVAL-IAM-001",
                "finding_id": "FND-" + "A" * 32,
                "rule_id": "IAM-001",
                "resource_type": "role",
                "resource_id": "evaluation-admin",
                "reason": "duplicate-decision-key",
                "counted_as_false_positive": False,
            }
        ]
        self.assertTrue(list(validator.iter_errors(uncounted_unexpected)))


if __name__ == "__main__":
    unittest.main()
