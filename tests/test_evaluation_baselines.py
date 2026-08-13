from __future__ import annotations

import ast
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.evaluation_baselines import (
    BaselineSummary,
    EvaluationBaselineError,
    build_baseline_outcomes,
    build_overlap_matrix,
    verify_baseline_artifacts,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OVERLAP_PATH = Path("evaluation/baseline-overlap-v1.0.json")
OUTCOMES_PATH = Path("evaluation/baseline-outcomes-v1.0.json")


class EvaluationBaselineTests(unittest.TestCase):
    def _copy_verification_root(self) -> Path:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        root = Path(temporary_directory.name)
        shutil.copytree(PROJECT_ROOT / "evaluation", root / "evaluation")
        shutil.copytree(PROJECT_ROOT / "schemas", root / "schemas")
        (root / "cloud_rules").mkdir()
        shutil.copy2(
            PROJECT_ROOT / "cloud_rules/rules-v1.0.json",
            root / "cloud_rules/rules-v1.0.json",
        )
        return root

    def _load(self, root: Path, path: Path) -> dict[str, Any]:
        return json.loads((root / path).read_text(encoding="utf-8"))

    def _write(self, root: Path, path: Path, value: dict[str, Any]) -> None:
        (root / path).write_text(
            json.dumps(value, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_frozen_baseline_artifacts_match_complete_replay(self):
        self.assertEqual(
            verify_baseline_artifacts(PROJECT_ROOT),
            BaselineSummary(
                rule_count=35,
                exact_rule_count=5,
                partial_rule_count=18,
                no_counterpart_rule_count=12,
                decision_count=24,
                positive_prediction_count=11,
                negative_prediction_count=13,
                exclusion_count=152,
            ),
        )

    def test_matrix_covers_catalog_once_in_catalog_order(self):
        catalog = self._load(PROJECT_ROOT, Path("cloud_rules/rules-v1.0.json"))
        matrix = build_overlap_matrix(PROJECT_ROOT)
        self.assertEqual(
            [rule["rule_id"] for rule in catalog["rules"]],
            [row["lab_rule_id"] for row in matrix["rows"]],
        )
        self.assertEqual(35, len({row["lab_rule_id"] for row in matrix["rows"]}))
        self.assertEqual(
            {"exact": 5, "partial": 18, "none": 12},
            {
                relationship: sum(
                    row["relationship"] == relationship for row in matrix["rows"]
                )
                for relationship in ("exact", "partial", "none")
            },
        )

    def test_only_exact_eligible_assertions_produce_decisions(self):
        matrix = self._load(PROJECT_ROOT, OVERLAP_PATH)
        outcomes = build_baseline_outcomes(PROJECT_ROOT, matrix)
        exact_rules = {
            row["lab_rule_id"]
            for row in matrix["rows"]
            if row["relationship"] == "exact"
        }
        self.assertEqual(
            {"IAM-006", "IAM-007", "IAM-013", "STO-004", "STO-005"},
            exact_rules,
        )
        self.assertTrue(outcomes["decisions"])
        self.assertTrue(
            all(decision["lab_rule_id"] in exact_rules for decision in outcomes["decisions"])
        )
        self.assertEqual(
            outcomes["summary"]["corpus_assertion_count"],
            len(outcomes["decisions"]) + len(outcomes["exclusions"]),
        )

    def test_sigma_release_inventory_is_pinned_and_has_no_exact_decisions(self):
        outcomes = self._load(PROJECT_ROOT, OUTCOMES_PATH)
        sigma = next(
            run for run in outcomes["baseline_runs"] if run["baseline_id"] == "sigma-core"
        )
        self.assertEqual("no-exact-overlap", sigma["execution_mode"])
        self.assertEqual(0, sigma["exact_rule_count"])
        self.assertEqual(0, sigma["decision_count"])
        self.assertEqual(12, len(sigma["release_inventory"]))
        self.assertEqual(
            12,
            len({record["source_path"] for record in sigma["release_inventory"]}),
        )
        self.assertTrue(
            all(len(record["sha256"]) == 64 for record in sigma["release_inventory"])
        )

    def test_verification_path_does_not_import_candidate_code(self):
        candidate_roots = {
            "cloud_security_lab",
            "cloudtrail_detector",
            "iam_analyzer",
            "network_analyzer",
            "storage_analyzer",
        }
        for source_name in ("evaluation_baselines.py", "evaluation_corpus.py"):
            with self.subTest(source=source_name):
                source_path = PROJECT_ROOT / "tools" / source_name
                tree = ast.parse(source_path.read_text(encoding="utf-8"))
                imported_modules: set[str] = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported_modules.update(alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module is not None:
                        imported_modules.add(node.module)

                self.assertFalse(
                    any(
                        module.split(".", 1)[0] in candidate_roots
                        for module in imported_modules
                    )
                )

    def test_overlap_matrix_tampering_is_rejected(self):
        root = self._copy_verification_root()
        matrix = self._load(root, OVERLAP_PATH)
        matrix["rows"][0]["rationale"] = "Tampered rationale."
        self._write(root, OVERLAP_PATH, matrix)

        with self.assertRaisesRegex(EvaluationBaselineError, "differs.*mapping"):
            verify_baseline_artifacts(root)

    def test_baseline_prediction_tampering_is_rejected(self):
        root = self._copy_verification_root()
        outcomes = self._load(root, OUTCOMES_PATH)
        outcomes["decisions"][0]["prediction"] = not outcomes["decisions"][0][
            "prediction"
        ]
        self._write(root, OUTCOMES_PATH, outcomes)

        with self.assertRaisesRegex(EvaluationBaselineError, "differ.*replay"):
            verify_baseline_artifacts(root)

    def test_noncanonical_artifact_bytes_are_rejected(self):
        for artifact_path in (OVERLAP_PATH, OUTCOMES_PATH):
            with self.subTest(artifact=artifact_path.name):
                root = self._copy_verification_root()
                artifact = root / artifact_path
                artifact.write_bytes(artifact.read_bytes() + b"\n")

                with self.assertRaisesRegex(
                    EvaluationBaselineError,
                    "canonical deterministic JSON",
                ):
                    verify_baseline_artifacts(root)

    def test_missing_assertion_partition_record_is_rejected(self):
        root = self._copy_verification_root()
        outcomes = self._load(root, OUTCOMES_PATH)
        outcomes["exclusions"].pop()
        outcomes["summary"]["exclusion_count"] -= 1
        self._write(root, OUTCOMES_PATH, outcomes)

        with self.assertRaisesRegex(EvaluationBaselineError, "differ.*replay"):
            verify_baseline_artifacts(root)

    def test_sigma_release_inventory_tampering_is_rejected(self):
        root = self._copy_verification_root()
        outcomes = self._load(root, OUTCOMES_PATH)
        sigma = next(
            run for run in outcomes["baseline_runs"] if run["baseline_id"] == "sigma-core"
        )
        sigma["release_inventory"][0]["sha256"] = "0" * 64
        self._write(root, OUTCOMES_PATH, outcomes)

        with self.assertRaisesRegex(EvaluationBaselineError, "differ.*replay"):
            verify_baseline_artifacts(root)

    def test_truth_and_candidate_fields_are_absent_from_outcomes(self):
        outcomes = self._load(PROJECT_ROOT, OUTCOMES_PATH)
        serialized = json.dumps(outcomes)
        self.assertNotIn('"truth_label"', serialized)
        self.assertNotIn('"expected_severity"', serialized)
        self.assertNotIn('"candidate_prediction"', serialized)
        self.assertFalse(outcomes["method"]["candidate_executed"])
        self.assertFalse(outcomes["method"]["candidate_imported"])
        self.assertFalse(outcomes["method"]["truth_labels_consumed"])


if __name__ == "__main__":
    unittest.main()
