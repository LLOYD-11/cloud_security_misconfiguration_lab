from __future__ import annotations

import unittest
from typing import cast

from tools.evaluation_runner import (
    VariantRun,
    _acceptance,
    _cloudtrail_correlation_ablation,
    _metric_block,
    _native_simplified_ablation,
    _network_context_ablation,
    _score_primary_runs,
    _wilson_interval,
)


class _Finding:
    def __init__(
        self,
        rule_id: str,
        resource_type: str,
        resource_id: str,
        severity: str,
        finding_id: str,
    ) -> None:
        self.rule_id = rule_id
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.severity = severity
        self.finding_id = finding_id


class _Run:
    def __init__(
        self,
        findings: tuple[_Finding, ...],
        *,
        module: str = "iam",
        findings_without_correlation: tuple[_Finding, ...] | None = None,
        incident_count: int = 0,
    ) -> None:
        self.findings = findings
        self.module = module
        self.findings_without_correlation = findings_without_correlation or findings
        self.incident_count = incident_count


class EvaluationRunnerTests(unittest.TestCase):
    def test_wilson_interval_handles_empty_and_perfect_samples(self) -> None:
        self.assertIsNone(_wilson_interval(0, 0))
        interval = _wilson_interval(4, 4)
        self.assertIsNotNone(interval)
        assert interval is not None
        self.assertAlmostEqual(1.0, interval["upper"])
        self.assertGreater(interval["lower"], 0.0)

    def test_metric_block_uses_null_for_undefined_ratios(self) -> None:
        block = _metric_block([])
        self.assertIsNone(block["scores"]["precision"])
        self.assertIsNone(block["scores"]["recall"])
        self.assertIsNone(block["scores"]["f1"])
        self.assertIsNone(block["scores"]["specificity"])

    def test_metric_block_counts_unexpected_predictions_as_false_positives(self) -> None:
        block = _metric_block(
            [
                {"outcome": "true-positive"},
                {"outcome": "true-negative"},
            ],
            extra_false_positives=1,
        )
        self.assertEqual(
            {
                "true_positive": 1,
                "false_positive": 1,
                "false_negative": 0,
                "true_negative": 1,
            },
            block["confusion"],
        )
        self.assertEqual(0.5, block["scores"]["precision"])
        self.assertEqual(0.5, block["scores"]["specificity"])

    def test_matcher_counts_negative_match_duplicate_and_undeclared_as_fp(self) -> None:
        corpus = {
            "cases": [
                {
                    "id": "EVAL-IAM-999",
                    "module": "iam",
                    "assertions": [
                        {
                            "id": "AST-IAM-999-01",
                            "rule_id": "IAM-001",
                            "resource_type": "role",
                            "resource_id": "declared",
                            "label": "negative",
                            "expected_severity": None,
                        }
                    ],
                }
            ]
        }
        finding = _Finding(
            "IAM-001",
            "role",
            "declared",
            "critical",
            "FND-00000000000000000000000000000001",
        )
        extra = _Finding(
            "IAM-002",
            "role",
            "extra",
            "medium",
            "FND-00000000000000000000000000000002",
        )
        results, unexpected = _score_primary_runs(
            corpus,
            {
                "EVAL-IAM-999": cast(
                    VariantRun,
                    _Run((finding, finding, extra)),
                )
            },
        )
        self.assertEqual("false-positive", results[0]["outcome"])
        self.assertEqual(2, results[0]["prediction_count"])
        self.assertEqual(1, results[0]["duplicate_prediction_count"])
        self.assertEqual(
            {"duplicate-decision-key", "undeclared-decision-key"},
            {record["reason"] for record in unexpected},
        )

    def test_correlation_ablation_compares_both_finding_paths(self) -> None:
        finding = _Finding(
            "CLD-001",
            "identity",
            "root",
            "critical",
            "FND-00000000000000000000000000000001",
        )
        run = cast(
            VariantRun,
            _Run(
                (finding,),
                module="cloudtrail",
                findings_without_correlation=(finding,),
                incident_count=2,
            ),
        )
        result = _cloudtrail_correlation_ablation({"EVAL-CLD-999": run})
        self.assertTrue(result["invariant_passed"])
        self.assertEqual(1.0, result["primary_decision_agreement"])
        self.assertEqual(2, result["changed_incident_count"])

    def test_representation_ablation_requires_decisions_and_severities(self) -> None:
        finding = _Finding(
            "IAM-001",
            "role",
            "same",
            "critical",
            "FND-00000000000000000000000000000001",
        )
        changed = _Finding(
            "IAM-001",
            "role",
            "same",
            "high",
            "FND-00000000000000000000000000000002",
        )
        result = _native_simplified_ablation(
            {
                "pair-a": [
                    cast(VariantRun, _Run((finding,))),
                    cast(VariantRun, _Run((finding,))),
                ],
                "pair-b": [
                    cast(VariantRun, _Run((finding,))),
                    cast(VariantRun, _Run((changed,))),
                ],
            }
        )
        self.assertFalse(result["invariant_passed"])
        self.assertEqual(1.0, result["primary_decision_agreement"])
        self.assertEqual(1, result["changed_severity_count"])

    def test_network_ablation_discloses_missing_frozen_context(self) -> None:
        result = _network_context_ablation(
            {
                "cases": [
                    {
                        "module": "network",
                        "input_variants": [
                            {
                                "files": [
                                    {
                                        "contract": (
                                            "schemas/simplified-network-input-v1.0.schema.json"
                                        )
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        )
        self.assertEqual(0, result["eligible_cases"])
        self.assertFalse(result["invariant_passed"])
        self.assertIsNone(result["primary_decision_agreement"])
        self.assertIn("Not estimable", result["notes"])

    def test_acceptance_reports_each_registered_failure(self) -> None:
        protocol = {
            "scoring": {
                "acceptance_thresholds": {
                    "minimum_overall_micro_f1": 0.9,
                    "minimum_per_module_precision": 0.9,
                    "minimum_per_module_recall": 0.9,
                    "maximum_critical_high_false_negatives": 0,
                    "minimum_native_simplified_decision_agreement": 1.0,
                    "maximum_unlabelled_predictions": 0,
                }
            }
        }
        overall = {"scores": {"f1": 0.89}}
        per_module = [
            {"module": "iam", "scores": {"precision": 0.89, "recall": 0.89}}
        ]
        assertions = [
            {
                "outcome": "false-negative",
                "expected_severity": "high",
            }
        ]
        unexpected = [{"reason": "undeclared-decision-key"}]
        ablations = [
            {
                "id": "native-simplified-equivalence",
                "primary_decision_agreement": 0.5,
            }
        ]

        result = _acceptance(
            protocol,
            overall,
            per_module,
            assertions,
            unexpected,
            ablations,
        )

        self.assertFalse(result["passed"])
        self.assertEqual(6, len(result["checks"]))
        self.assertTrue(all(not check["passed"] for check in result["checks"]))


if __name__ == "__main__":
    unittest.main()
