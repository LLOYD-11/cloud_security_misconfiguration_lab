from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tools.evaluation_replay import replay_evaluation
from tools.evaluation_runner import (
    RESULTS_PATH,
    EvaluationRunError,
    EvaluationSummary,
    _validate_result_invariants,
    build_evaluation_results,
    verify_evaluation_results,
    write_evaluation_results,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER_FREEZE_REVISION = "d316a1c696b404f741fe121fab309ec738019582"
RESULT_SHA256 = "5bce3ded5a87bd6e7ef35db432defea54f78908ad6cf656ec0e00cb9cc7c6e34"


class EvaluationResultTests(unittest.TestCase):
    def _load_result(self) -> dict[str, Any]:
        return json.loads((PROJECT_ROOT / RESULTS_PATH).read_text(encoding="utf-8"))

    def _temporary_result(self, content: bytes) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / RESULTS_PATH.name
        path.write_bytes(content)
        return path

    def _verify_in_process(self, path: Path | None = None) -> EvaluationSummary:
        # The isolated replay below proves candidate identity and computation.
        # Injecting its frozen result here exercises verifier-only paths without
        # substituting a later analyzer implementation for candidate 2.1.1.
        with (
            patch("tools.evaluation_runner._validate_candidate_identity"),
            patch(
                "tools.evaluation_runner.build_evaluation_results",
                return_value=self._load_result(),
            ),
        ):
            return verify_evaluation_results(PROJECT_ROOT, path or PROJECT_ROOT / RESULTS_PATH)

    def test_committed_primary_result_replays_exactly(self) -> None:
        self.assertEqual(
            replay_evaluation(PROJECT_ROOT),
            "Independent evaluation verified: 168 scored, 8 excluded; "
            "TP=77, FP=2, FN=1, TN=90; precision=0.9747, recall=0.9872, "
            "F1=0.9809, specificity=0.9783; severity=77/77; acceptance=failed.",
        )
        self.assertEqual(
            self._verify_in_process(),
            EvaluationSummary(
                scored_assertions=168,
                excluded_assertions=8,
                true_positive=77,
                false_positive=2,
                false_negative=1,
                true_negative=90,
                precision=0.9746835443037974,
                recall=0.9871794871794872,
                f1=0.980891719745223,
                specificity=0.9782608695652174,
                severity_matches=77,
                matched_positives=77,
                acceptance_passed=False,
            ),
        )

    def test_revealed_mfa_case_is_fixed_as_development_regression(self) -> None:
        frozen = self._load_result()
        with patch("tools.evaluation_runner._validate_candidate_identity"):
            current = build_evaluation_results(
                PROJECT_ROOT,
                recorded_environment=frozen["environment"],
                recorded_evaluated_at=str(frozen["evaluated_at"]),
            )
        regression = next(
            record
            for record in current["assertion_results"]
            if record["case_id"] == "EVAL-IAM-006"
            and record["rule_id"] == "IAM-005"
        )

        self.assertEqual("true-positive", regression["outcome"])
        self.assertNotEqual(frozen, current)
        self.assertEqual(
            RESULT_SHA256,
            hashlib.sha256((PROJECT_ROOT / RESULTS_PATH).read_bytes()).hexdigest(),
        )

    def test_runner_and_primary_result_match_pre_execution_freeze(self) -> None:
        result_bytes = (PROJECT_ROOT / RESULTS_PATH).read_bytes()
        self.assertEqual(RESULT_SHA256, hashlib.sha256(result_bytes).hexdigest())
        subprocess.run(
            [
                "git",
                "merge-base",
                "--is-ancestor",
                RUNNER_FREEZE_REVISION,
                "HEAD",
            ],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        comparison = subprocess.run(
            [
                "git",
                "diff",
                "--exit-code",
                RUNNER_FREEZE_REVISION,
                "--",
                "tools/evaluation_runner.py",
            ],
            cwd=PROJECT_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, comparison.returncode, comparison.stdout + comparison.stderr)

    def test_result_preserves_failures_and_non_gating_limitation(self) -> None:
        result = self._load_result()
        failed_checks = {
            check["id"] for check in result["acceptance"]["checks"] if not check["passed"]
        }
        disagreements = [
            record
            for record in result["assertion_results"]
            if record["outcome"] in {"false-positive", "false-negative"}
        ]

        self.assertFalse(result["acceptance"]["passed"])
        self.assertEqual(
            {"storage-precision", "unlabelled-predictions"},
            failed_checks,
        )
        self.assertEqual(
            [("EVAL-IAM-006", "IAM-005", "false-negative")],
            [
                (record["case_id"], record["rule_id"], record["outcome"])
                for record in disagreements
            ],
        )
        self.assertEqual(
            [
                ("EVAL-STO-007", "STO-001"),
                ("EVAL-STO-008", "STO-001"),
            ],
            [
                (record["case_id"], record["rule_id"])
                for record in result["unexpected_predictions"]
            ],
        )
        self.assertTrue(result["validity"]["valid"])
        self.assertEqual(1, len(result["validity"]["issues"]))
        self.assertIn("Non-gating limitation", result["validity"]["issues"][0])

    def test_tampered_result_is_rejected(self) -> None:
        result = self._load_result()
        result["counts"]["matched_positive_count"] -= 1
        path = self._temporary_result((json.dumps(result, indent=2) + "\n").encode())

        with self.assertRaisesRegex(
            EvaluationRunError,
            "differ from deterministic candidate execution",
        ):
            self._verify_in_process(path)

    def test_noncanonical_result_bytes_are_rejected(self) -> None:
        content = (PROJECT_ROOT / RESULTS_PATH).read_bytes() + b"\n"
        path = self._temporary_result(content)

        with self.assertRaisesRegex(
            EvaluationRunError,
            "canonical deterministic JSON",
        ):
            self._verify_in_process(path)

    def test_result_invariants_reject_tampered_counts(self) -> None:
        result = copy.deepcopy(self._load_result())
        result["counts"]["scored_assertion_count"] -= 1

        with self.assertRaisesRegex(EvaluationRunError, "Scored assertion count"):
            _validate_result_invariants(result)

    def test_primary_result_cannot_be_overwritten(self) -> None:
        with self.assertRaisesRegex(EvaluationRunError, "cannot be overwritten"):
            write_evaluation_results(PROJECT_ROOT)


if __name__ == "__main__":
    unittest.main()
