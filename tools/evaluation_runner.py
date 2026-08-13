"""Execute and verify the frozen M12 independent evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import subprocess
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from cloud_findings import Finding
from cloud_security_lab import __version__
from cloud_security_lab.normalizers.cloudtrail import load_aws_cloudtrail_environment
from cloud_security_lab.normalizers.ec2 import load_aws_ec2_environment
from cloud_security_lab.normalizers.iam import load_aws_iam_environment
from cloud_security_lab.normalizers.s3 import load_aws_s3_environment
from cloudtrail_detector.detector import analyze_activity
from iam_analyzer.analyzer import analyze_environment as analyze_iam
from network_analyzer.analyzer import analyze_environment as analyze_network
from storage_analyzer.analyzer import analyze_environment as analyze_storage
from tools.evaluation_baselines import verify_baseline_artifacts
from tools.evaluation_corpus import verify_corpus

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = Path("evaluation/protocol-v1.0.json")
CORPUS_PATH = Path("evaluation/corpus-manifest-v1.0.json")
OVERLAP_PATH = Path("evaluation/baseline-overlap-v1.0.json")
BASELINE_OUTCOMES_PATH = Path("evaluation/baseline-outcomes-v1.0.json")
RESULTS_PATH = Path("evaluation/results-v1.0.json")
RESULTS_SCHEMA_PATH = Path("schemas/evaluation-results-v1.0.schema.json")
RULE_CATALOG_PATH = Path("cloud_rules/rules-v1.0.json")
CANDIDATE_REVISION = "6d71c99914a38b6e161bc9cf56407eb1757b8c9a"
CANDIDATE_VERSION = "2.1.1"
EVALUATION_ID = "EVAL-RUN-2026-08-13-PRIMARY"
EVALUATION_COMMAND = ["python", "-m", "tools.evaluation_runner", "--write"]
AS_OF = date(2026, 8, 13)
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MODULE_ORDER = ("iam", "storage", "network", "cloudtrail")


class EvaluationRunError(ValueError):
    """Raised when the frozen evaluation cannot be executed or verified."""


@dataclass(frozen=True)
class EvaluationSummary:
    """Compact summary of a verified evaluation result."""

    scored_assertions: int
    excluded_assertions: int
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float | None
    recall: float | None
    f1: float | None
    specificity: float | None
    severity_matches: int
    matched_positives: int
    acceptance_passed: bool


@dataclass(frozen=True)
class VariantRun:
    """One candidate invocation over one retained input representation."""

    case_id: str
    module: str
    variant_id: str
    input_form: str
    equivalence_group: str | None
    findings: tuple[Finding, ...]
    findings_without_correlation: tuple[Finding, ...]
    incident_count: int


Analyzer = Callable[[dict[str, Any]], list[Finding]]

ANALYZERS: dict[str, Analyzer] = {
    "iam": analyze_iam,
    "storage": analyze_storage,
    "network": analyze_network,
}


def _read_bytes(path: Path, *, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise EvaluationRunError(f"{label} must be a regular file: {path}.")
    with path.open("rb") as handle:
        content = handle.read(MAX_ARTIFACT_BYTES + 1)
    if len(content) > MAX_ARTIFACT_BYTES:
        raise EvaluationRunError(
            f"{label} exceeds the {MAX_ARTIFACT_BYTES:,}-byte limit: {path}."
        )
    return content


def _load_json(path: Path, *, label: str) -> Any:
    try:
        return json.loads(_read_bytes(path, label=label))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvaluationRunError(f"{label} is not valid UTF-8 JSON: {path}.") from error


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=False) + "\n").encode("utf-8")


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(_read_bytes(path, label="Artifact"))


def _artifact(root: Path, path: Path, version: str) -> dict[str, str]:
    return {
        "path": path.as_posix(),
        "version": version,
        "sha256": _sha256_file(root / path),
    }


def _schema_error_message(error: Any) -> str:
    location = "/".join(str(value) for value in error.absolute_path) or "<root>"
    return f"{location}: {error.message}"


def _validate_schema(instance: Any, schema: Any) -> None:
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        raise EvaluationRunError(f"Invalid evaluation results schema: {error}") from error
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(instance),
        key=lambda error: tuple(str(value) for value in error.absolute_path),
    )
    if errors:
        raise EvaluationRunError(
            "Evaluation results violate their JSON Schema: "
            + _schema_error_message(errors[0])
        )


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise EvaluationRunError(f"Unable to inspect Git state: {error}") from error
    return result.stdout.strip()


def _validate_candidate_identity(root: Path, protocol: dict[str, Any]) -> None:
    candidate = protocol["candidate"]
    if candidate["analyzer_revision"] != CANDIDATE_REVISION:
        raise EvaluationRunError("Protocol candidate revision differs from the runner freeze.")
    if candidate["package_version"] != CANDIDATE_VERSION:
        raise EvaluationRunError("Protocol candidate package version differs from the runner freeze.")
    if __version__ != CANDIDATE_VERSION:
        raise EvaluationRunError("Imported candidate package version differs from the runner freeze.")
    catalog = candidate["rule_catalog"]
    if _sha256_file(root / RULE_CATALOG_PATH) != catalog["sha256"]:
        raise EvaluationRunError("Frozen candidate rule-catalog digest changed.")
    try:
        _git(root, "cat-file", "-e", f"{CANDIDATE_REVISION}^{{commit}}")
    except EvaluationRunError as error:
        raise EvaluationRunError("Frozen candidate revision is absent from Git history.") from error
    changed = _git(
        root,
        "diff",
        "--name-only",
        CANDIDATE_REVISION,
        "--",
        "cloud_findings",
        "cloud_incidents",
        "cloud_inputs",
        "cloud_rules",
        "cloud_security_lab",
        "cloudtrail_detector",
        "iam_analyzer",
        "network_analyzer",
        "storage_analyzer",
    )
    if changed:
        raise EvaluationRunError(
            "Candidate runtime differs from the frozen analyzer revision: "
            + ", ".join(changed.splitlines())
        )


def _variant_paths(root: Path, variant: dict[str, Any]) -> list[Path]:
    paths = [root / str(record["path"]) for record in variant["files"]]
    for path, record in zip(paths, variant["files"]):
        if _sha256_file(path) != record["sha256"]:
            raise EvaluationRunError(f"Evaluation evidence digest changed: {record['path']}.")
    return paths


def _load_variant_environment(
    root: Path,
    module: str,
    variant: dict[str, Any],
) -> dict[str, Any]:
    paths = _variant_paths(root, variant)
    if variant["input_form"] == "simplified":
        if len(paths) != 1:
            raise EvaluationRunError("Simplified variants must contain exactly one JSON file.")
        value = _load_json(paths[0], label="Simplified evaluation evidence")
        if not isinstance(value, dict):
            raise EvaluationRunError("Simplified evaluation evidence must be a JSON object.")
        return value
    if module == "iam":
        json_paths = [path for path in paths if path.suffix == ".json"]
        csv_paths = [path for path in paths if path.suffix == ".csv"]
        if len(json_paths) != 1 or len(csv_paths) != 1:
            raise EvaluationRunError("Native IAM variants require one JSON and one CSV file.")
        return load_aws_iam_environment(
            json_paths[0],
            csv_paths[0],
            as_of=AS_OF,
        ).environment
    if module == "storage":
        if len(paths) != 1:
            raise EvaluationRunError("Native storage variants require one evidence bundle.")
        return load_aws_s3_environment(paths[0]).environment
    if module == "network":
        if len(paths) != 1:
            raise EvaluationRunError("Native network variants require one EC2 response.")
        return load_aws_ec2_environment(paths[0]).environment
    if module == "cloudtrail":
        return load_aws_cloudtrail_environment(paths).environment
    raise EvaluationRunError(f"Unsupported evaluation module: {module}.")


def _execute_variant(
    root: Path,
    case: dict[str, Any],
    variant: dict[str, Any],
) -> VariantRun:
    module = str(case["module"])
    environment = _load_variant_environment(root, module, variant)
    if module == "cloudtrail":
        with patch("cloudtrail_detector.detector.correlate_incidents", return_value=[]):
            findings_only = analyze_activity(environment)
        analysis = analyze_activity(environment)
        findings = analysis.findings
        findings_without_correlation = findings_only.findings
        incident_count = len(analysis.incidents)
    else:
        findings = tuple(ANALYZERS[module](environment))
        findings_without_correlation = tuple(findings)
        incident_count = 0
    return VariantRun(
        case_id=str(case["id"]),
        module=module,
        variant_id=str(variant["id"]),
        input_form=str(variant["input_form"]),
        equivalence_group=(
            str(variant["equivalence_group"])
            if variant["equivalence_group"] is not None
            else None
        ),
        findings=tuple(findings),
        findings_without_correlation=tuple(findings_without_correlation),
        incident_count=incident_count,
    )


def _finding_key(finding: Finding) -> tuple[str, str, str]:
    return finding.rule_id, finding.resource_type, finding.resource_id


def _decision_key(assertion: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(assertion["rule_id"]),
        str(assertion["resource_type"]),
        str(assertion["resource_id"]),
    )


def _wilson_interval(successes: int, total: int) -> dict[str, float] | None:
    if total == 0:
        return None
    z = 1.959963984540054
    ratio = successes / total
    denominator = 1 + (z * z / total)
    center = (ratio + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(
        (ratio * (1 - ratio) / total) + (z * z / (4 * total * total))
    ) / denominator
    return {
        "lower": max(0.0, center - margin),
        "upper": min(1.0, center + margin),
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _metric_block(
    records: Iterable[dict[str, Any]],
    *,
    module: str | None = None,
    rule_id: str | None = None,
    extra_false_positives: int = 0,
) -> dict[str, Any]:
    counts = Counter(record["outcome"] for record in records)
    tp = counts["true-positive"]
    fp = counts["false-positive"] + extra_false_positives
    fn = counts["false-negative"]
    tn = counts["true-negative"]
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall > 0
        else None
    )
    block: dict[str, Any] = {
        "confusion": {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": tn,
        },
        "scores": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "specificity": _ratio(tn, tn + fp),
        },
        "confidence_intervals": {
            "precision": _wilson_interval(tp, tp + fp),
            "recall": _wilson_interval(tp, tp + fn),
            "specificity": _wilson_interval(tn, tn + fp),
        },
    }
    if module is not None:
        block["module"] = module
    if rule_id is not None:
        block["rule_id"] = rule_id
    return block


def _score_primary_runs(
    corpus: dict[str, Any],
    primary_runs: dict[str, VariantRun],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    assertion_results: list[dict[str, Any]] = []
    unexpected_predictions: list[dict[str, Any]] = []
    for case in corpus["cases"]:
        case_id = str(case["id"])
        run = primary_runs[case_id]
        by_key: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
        for finding in run.findings:
            by_key[_finding_key(finding)].append(finding)
        declared_keys = {_decision_key(assertion) for assertion in case["assertions"]}

        for assertion in case["assertions"]:
            key = _decision_key(assertion)
            matches = by_key.get(key, [])
            label = str(assertion["label"])
            if label == "positive":
                outcome = "true-positive" if matches else "false-negative"
            elif label == "negative":
                outcome = "false-positive" if matches else "true-negative"
            else:
                outcome = "excluded"
            observed_severity = matches[0].severity if matches else None
            expected_severity = assertion["expected_severity"]
            severity_match = (
                observed_severity == expected_severity
                if label == "positive" and matches
                else None
            )
            duplicate_count = max(0, len(matches) - 1)
            if outcome == "true-positive":
                message = (
                    "A matching candidate finding was observed; extra matches are counted "
                    "separately as false positives."
                    if duplicate_count
                    else "Exactly one matching candidate finding was observed."
                )
            elif outcome == "false-negative":
                message = "No matching candidate finding was observed."
            elif outcome == "true-negative":
                message = "No matching candidate finding was observed."
            elif outcome == "false-positive":
                message = "A candidate finding matched a negative assertion."
            else:
                message = f"The {label} assertion is excluded from classification metrics."
            assertion_results.append(
                {
                    "case_id": case_id,
                    "assertion_id": assertion["id"],
                    "module": case["module"],
                    "rule_id": assertion["rule_id"],
                    "resource_type": assertion["resource_type"],
                    "resource_id": assertion["resource_id"],
                    "truth_label": label,
                    "prediction_count": len(matches),
                    "duplicate_prediction_count": duplicate_count,
                    "outcome": outcome,
                    "expected_severity": expected_severity,
                    "observed_severity": observed_severity,
                    "severity_match": severity_match,
                    "message": message,
                }
            )
            for duplicate in matches[1:]:
                unexpected_predictions.append(
                    {
                        "case_id": case_id,
                        "finding_id": duplicate.finding_id,
                        "rule_id": duplicate.rule_id,
                        "resource_type": duplicate.resource_type,
                        "resource_id": duplicate.resource_id,
                        "reason": "duplicate-decision-key",
                        "counted_as_false_positive": True,
                    }
                )

        for finding in run.findings:
            if _finding_key(finding) not in declared_keys:
                unexpected_predictions.append(
                    {
                        "case_id": case_id,
                        "finding_id": finding.finding_id,
                        "rule_id": finding.rule_id,
                        "resource_type": finding.resource_type,
                        "resource_id": finding.resource_id,
                        "reason": "undeclared-decision-key",
                        "counted_as_false_positive": True,
                    }
                )
    return assertion_results, unexpected_predictions


def _group_unexpected(
    unexpected: Sequence[dict[str, Any]],
    primary_runs: dict[str, VariantRun],
) -> tuple[Counter[str], Counter[str]]:
    module_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    for record in unexpected:
        module_counts[primary_runs[record["case_id"]].module] += 1
        rule_counts[record["rule_id"]] += 1
    return module_counts, rule_counts


def _native_simplified_ablation(
    paired_runs: dict[str, list[VariantRun]],
) -> dict[str, Any]:
    decision_agreements = 0
    changed_severity_count = 0
    unexpected_change_count = 0
    for runs in paired_runs.values():
        if len(runs) != 2:
            raise EvaluationRunError("Each representation pair must have exactly two runs.")
        left, right = runs
        left_map = {_finding_key(finding): finding.severity for finding in left.findings}
        right_map = {_finding_key(finding): finding.severity for finding in right.findings}
        decision_equal = set(left_map) == set(right_map)
        severity_changes = sum(
            left_map[key] != right_map[key] for key in set(left_map).intersection(right_map)
        )
        changed_severity_count += severity_changes
        if decision_equal:
            decision_agreements += 1
        unexpected_change_count += len(set(left_map).symmetric_difference(right_map))
    total = len(paired_runs)
    agreement = _ratio(decision_agreements, total)
    return {
        "id": "native-simplified-equivalence",
        "eligible_cases": total,
        "invariant_passed": (
            total > 0
            and decision_agreements == total
            and changed_severity_count == 0
            and unexpected_change_count == 0
        ),
        "primary_decision_agreement": agreement,
        "changed_severity_count": changed_severity_count,
        "changed_incident_count": 0,
        "unexpected_change_count": unexpected_change_count,
        "notes": (
            "Compared complete rule/resource decision sets and severities for every frozen "
            "native/simplified equivalence group."
        ),
    }


def _network_context_ablation(corpus: dict[str, Any]) -> dict[str, Any]:
    eligible = sum(
        any(
            record["contract"] == "schemas/network-reachability-context-v1.0.schema.json"
            for variant in case["input_variants"]
            for record in variant["files"]
        )
        for case in corpus["cases"]
        if case["module"] == "network"
    )
    return {
        "id": "network-reachability-context",
        "eligible_cases": eligible,
        "invariant_passed": eligible > 0,
        "primary_decision_agreement": None,
        "changed_severity_count": 0,
        "changed_incident_count": 0,
        "unexpected_change_count": 0,
        "notes": (
            "Not estimable: the frozen R2 corpus contains no reachability-context artifact; "
            "post-freeze evidence was not added."
        ),
    }


def _cloudtrail_correlation_ablation(
    primary_runs: dict[str, VariantRun],
) -> dict[str, Any]:
    cloudtrail_runs = [run for run in primary_runs.values() if run.module == "cloudtrail"]
    decision_agreements = 0
    changed_severity_count = 0
    unexpected_change_count = 0
    for run in cloudtrail_runs:
        correlated = {_finding_key(finding): finding.severity for finding in run.findings}
        uncorrelated = {
            _finding_key(finding): finding.severity
            for finding in run.findings_without_correlation
        }
        if set(correlated) == set(uncorrelated):
            decision_agreements += 1
        unexpected_change_count += len(set(correlated).symmetric_difference(uncorrelated))
        changed_severity_count += sum(
            correlated[key] != uncorrelated[key]
            for key in set(correlated).intersection(uncorrelated)
        )
    changed_incidents = sum(run.incident_count for run in cloudtrail_runs)
    eligible = len(cloudtrail_runs)
    return {
        "id": "cloudtrail-incident-correlation",
        "eligible_cases": eligible,
        "invariant_passed": (
            eligible > 0
            and decision_agreements == eligible
            and changed_severity_count == 0
            and unexpected_change_count == 0
        ),
        "primary_decision_agreement": _ratio(decision_agreements, eligible),
        "changed_severity_count": changed_severity_count,
        "changed_incident_count": changed_incidents,
        "unexpected_change_count": unexpected_change_count,
        "notes": (
            "Compared findings from correlation-disabled and correlation-enabled executions; "
            f"correlation added {changed_incidents} incident(s)."
        ),
    }


def _baseline_comparisons(
    baseline_outcomes: dict[str, Any],
    primary_runs: dict[str, VariantRun],
) -> list[dict[str, Any]]:
    predictions = {
        case_id: {_finding_key(finding) for finding in run.findings}
        for case_id, run in primary_runs.items()
    }
    records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for decision in baseline_outcomes["decisions"]:
        key = (
            str(decision["lab_rule_id"]),
            str(decision["resource_type"]),
            str(decision["resource_id"]),
        )
        lab_prediction = key in predictions[str(decision["case_id"])]
        baseline_prediction = bool(decision["prediction"])
        if lab_prediction != baseline_prediction:
            records[str(decision["baseline_id"])].append(
                {
                    "case_id": decision["case_id"],
                    "lab_rule_id": decision["lab_rule_id"],
                    "baseline_check_id": decision["baseline_check_ids"][0],
                    "lab_prediction": lab_prediction,
                    "baseline_prediction": baseline_prediction,
                    "category": "implementation",
                    "explanation": (
                        "Equivalent frozen predicates produced different binary decisions over "
                        "the same retained simplified evidence."
                    ),
                }
            )
    comparisons: list[dict[str, Any]] = []
    for run in baseline_outcomes["baseline_runs"]:
        baseline_id = str(run["baseline_id"])
        eligible = int(run["decision_count"])
        disagreements = records[baseline_id]
        agreement_count = eligible - len(disagreements)
        comparisons.append(
            {
                "baseline_id": baseline_id,
                "eligible_decisions": eligible,
                "agreements": agreement_count,
                "disagreements": len(disagreements),
                "agreement_rate": _ratio(agreement_count, eligible),
                "disagreement_records": disagreements,
            }
        )
    return comparisons


def _acceptance_check(
    check_id: str,
    observed: float,
    operator: str,
    threshold: float,
) -> dict[str, Any]:
    operations = {
        ">=": lambda: observed >= threshold,
        "<=": lambda: observed <= threshold,
        "==": lambda: observed == threshold,
    }
    return {
        "id": check_id,
        "observed": observed,
        "operator": operator,
        "threshold": threshold,
        "passed": operations[operator](),
    }


def _acceptance(
    protocol: dict[str, Any],
    overall: dict[str, Any],
    per_module: list[dict[str, Any]],
    assertion_results: list[dict[str, Any]],
    unexpected_predictions: list[dict[str, Any]],
    ablations: list[dict[str, Any]],
) -> dict[str, Any]:
    thresholds = protocol["scoring"]["acceptance_thresholds"]
    native_ablation = next(
        record for record in ablations if record["id"] == "native-simplified-equivalence"
    )
    native_agreement = native_ablation["primary_decision_agreement"]
    if native_agreement is None:
        native_agreement = 0.0
    critical_high_false_negatives = sum(
        record["outcome"] == "false-negative"
        and record["expected_severity"] in {"critical", "high"}
        for record in assertion_results
    )
    checks = [
        _acceptance_check(
            "overall-micro-f1",
            float(overall["scores"]["f1"] or 0.0),
            ">=",
            float(thresholds["minimum_overall_micro_f1"]),
        )
    ]
    for module in per_module:
        module_id = str(module["module"])
        checks.append(
            _acceptance_check(
                f"{module_id}-precision",
                float(module["scores"]["precision"] or 0.0),
                ">=",
                float(thresholds["minimum_per_module_precision"]),
            )
        )
        checks.append(
            _acceptance_check(
                f"{module_id}-recall",
                float(module["scores"]["recall"] or 0.0),
                ">=",
                float(thresholds["minimum_per_module_recall"]),
            )
        )
    checks.extend(
        (
            _acceptance_check(
                "critical-high-false-negatives",
                float(critical_high_false_negatives),
                "<=",
                float(thresholds["maximum_critical_high_false_negatives"]),
            ),
            _acceptance_check(
                "native-simplified-decision-agreement",
                float(native_agreement),
                "==",
                float(thresholds["minimum_native_simplified_decision_agreement"]),
            ),
            _acceptance_check(
                "unlabelled-predictions",
                float(
                    sum(
                        record["reason"] == "undeclared-decision-key"
                        for record in unexpected_predictions
                    )
                ),
                "<=",
                float(thresholds["maximum_unlabelled_predictions"]),
            ),
        )
    )
    return {"passed": all(check["passed"] for check in checks), "checks": checks}


def build_evaluation_results(
    root: Path = PROJECT_ROOT,
    *,
    recorded_environment: dict[str, Any] | None = None,
    recorded_evaluated_at: str | None = None,
) -> dict[str, Any]:
    """Execute the registered primary run and build its complete result artifact."""

    root = root.resolve(strict=True)
    verify_corpus(root, CORPUS_PATH)
    verify_baseline_artifacts(root)
    protocol = _load_json(root / PROTOCOL_PATH, label="Evaluation protocol")
    corpus = _load_json(root / CORPUS_PATH, label="Evaluation corpus")
    overlap = _load_json(root / OVERLAP_PATH, label="Baseline overlap matrix")
    baseline_outcomes = _load_json(
        root / BASELINE_OUTCOMES_PATH,
        label="Baseline outcomes",
    )
    catalog = _load_json(root / RULE_CATALOG_PATH, label="Rule catalog")
    _validate_candidate_identity(root, protocol)
    if recorded_environment is None:
        current_status = _git(root, "status", "--porcelain")
        if current_status:
            raise EvaluationRunError(
                "The first candidate execution requires a clean Git worktree."
            )
        environment_record = {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "command": EVALUATION_COMMAND,
            "clean_worktree": True,
        }
        evaluated_at = _utc_now()
    else:
        environment_record = dict(recorded_environment)
        if recorded_evaluated_at is None:
            raise EvaluationRunError(
                "Verification requires the original evaluated_at timestamp."
            )
        evaluated_at = recorded_evaluated_at

    primary_runs: dict[str, VariantRun] = {}
    paired_runs: dict[str, list[VariantRun]] = defaultdict(list)
    for case in corpus["cases"]:
        variants = case["input_variants"]
        simplified = [variant for variant in variants if variant["input_form"] == "simplified"]
        if len(simplified) != 1:
            raise EvaluationRunError(
                f"Case {case['id']} must have exactly one simplified primary variant."
            )
        primary = _execute_variant(root, case, simplified[0])
        primary_runs[str(case["id"])] = primary
        for variant in variants:
            group = variant["equivalence_group"]
            if group is None:
                continue
            run = primary if variant is simplified[0] else _execute_variant(root, case, variant)
            paired_runs[str(group)].append(run)

    assertion_results, unexpected_predictions = _score_primary_runs(corpus, primary_runs)
    scored = [record for record in assertion_results if record["outcome"] != "excluded"]
    module_unexpected, rule_unexpected = _group_unexpected(
        unexpected_predictions,
        primary_runs,
    )
    overall = _metric_block(scored, extra_false_positives=len(unexpected_predictions))
    per_module = [
        _metric_block(
            (record for record in scored if record["module"] == module),
            module=module,
            extra_false_positives=module_unexpected[module],
        )
        for module in MODULE_ORDER
    ]
    module_by_rule = {
        str(rule["rule_id"]): str(rule["module"]) for rule in catalog["rules"]
    }
    per_rule = [
        _metric_block(
            (record for record in scored if record["rule_id"] == rule_id),
            module=module_by_rule[rule_id],
            rule_id=rule_id,
            extra_false_positives=rule_unexpected[rule_id],
        )
        for rule_id in module_by_rule
    ]
    ablations = [
        _native_simplified_ablation(paired_runs),
        _network_context_ablation(corpus),
        _cloudtrail_correlation_ablation(primary_runs),
    ]
    acceptance = _acceptance(
        protocol,
        overall,
        per_module,
        assertion_results,
        unexpected_predictions,
        ablations,
    )
    validity_issues: list[str] = []
    network_ablation = ablations[1]
    if network_ablation["eligible_cases"] == 0:
        validity_issues.append(
            "Non-gating limitation: the registered network reachability ablation was not "
            "estimable because the frozen corpus retained no reachability-context artifact."
        )
    return {
        "schema_version": "1.0",
        "evaluation_id": EVALUATION_ID,
        "evaluated_at": evaluated_at,
        "protocol": _artifact(root, PROTOCOL_PATH, str(protocol["protocol_version"])),
        "corpus": _artifact(root, CORPUS_PATH, str(corpus["corpus_version"])),
        "overlap_matrix": _artifact(root, OVERLAP_PATH, str(overlap["matrix_version"])),
        "candidate": {
            "analyzer_revision": CANDIDATE_REVISION,
            "package_version": CANDIDATE_VERSION,
            "rule_catalog_sha256": _sha256_file(root / RULE_CATALOG_PATH),
        },
        "environment": environment_record,
        "validity": {"valid": True, "issues": validity_issues},
        "counts": {
            "case_count": len(corpus["cases"]),
            "scored_assertion_count": len(scored),
            "excluded_assertion_count": len(assertion_results) - len(scored),
            "unlabelled_prediction_count": sum(
                record["reason"] == "undeclared-decision-key"
                for record in unexpected_predictions
            ),
            "duplicate_prediction_count": sum(
                record["reason"] == "duplicate-decision-key"
                for record in unexpected_predictions
            ),
            "matched_positive_count": sum(
                record["outcome"] == "true-positive" for record in assertion_results
            ),
            "severity_match_count": sum(
                record["severity_match"] is True for record in assertion_results
            ),
        },
        "overall": overall,
        "per_module": per_module,
        "per_rule": per_rule,
        "assertion_results": assertion_results,
        "unexpected_predictions": unexpected_predictions,
        "baseline_comparisons": _baseline_comparisons(
            baseline_outcomes,
            primary_runs,
        ),
        "ablations": ablations,
        "acceptance": acceptance,
    }


def _validate_result_invariants(result: dict[str, Any]) -> None:
    assertions = result["assertion_results"]
    scored = [record for record in assertions if record["outcome"] != "excluded"]
    excluded = [record for record in assertions if record["outcome"] == "excluded"]
    counts = result["counts"]
    if counts["scored_assertion_count"] != len(scored):
        raise EvaluationRunError("Scored assertion count does not match raw decisions.")
    if counts["excluded_assertion_count"] != len(excluded):
        raise EvaluationRunError("Excluded assertion count does not match raw decisions.")
    if len({(record["case_id"], record["assertion_id"]) for record in assertions}) != len(
        assertions
    ):
        raise EvaluationRunError("Assertion results contain duplicate identities.")
    unexpected = result["unexpected_predictions"]
    if counts["unlabelled_prediction_count"] != sum(
        record["reason"] == "undeclared-decision-key" for record in unexpected
    ):
        raise EvaluationRunError("Unlabelled prediction count does not match raw records.")
    if counts["duplicate_prediction_count"] != sum(
        record["reason"] == "duplicate-decision-key" for record in unexpected
    ):
        raise EvaluationRunError("Duplicate prediction count does not match raw records.")
    if counts["matched_positive_count"] != sum(
        record["outcome"] == "true-positive" for record in assertions
    ):
        raise EvaluationRunError("Matched-positive count does not match raw decisions.")
    if counts["severity_match_count"] != sum(
        record["severity_match"] is True for record in assertions
    ):
        raise EvaluationRunError("Severity-match count does not match raw decisions.")

    expected_overall = _metric_block(
        scored,
        extra_false_positives=len(unexpected),
    )
    if result["overall"] != expected_overall:
        raise EvaluationRunError("Overall metrics do not match raw decisions.")

    case_modules = {record["case_id"]: record["module"] for record in assertions}
    module_unexpected = Counter(case_modules[record["case_id"]] for record in unexpected)
    expected_modules = [
        _metric_block(
            (record for record in scored if record["module"] == module),
            module=module,
            extra_false_positives=module_unexpected[module],
        )
        for module in MODULE_ORDER
    ]
    if result["per_module"] != expected_modules:
        raise EvaluationRunError("Per-module metrics do not match raw decisions.")

    result_rules = [(record["module"], record["rule_id"]) for record in result["per_rule"]]
    if len(result_rules) != len(set(result_rules)):
        raise EvaluationRunError("Per-rule metrics contain duplicate rule identities.")
    rule_unexpected = Counter(record["rule_id"] for record in unexpected)
    expected_rules = [
        _metric_block(
            (record for record in scored if record["rule_id"] == rule_id),
            module=module,
            rule_id=rule_id,
            extra_false_positives=rule_unexpected[rule_id],
        )
        for module, rule_id in result_rules
    ]
    if result["per_rule"] != expected_rules:
        raise EvaluationRunError("Per-rule metrics do not match raw decisions.")

    for comparison in result["baseline_comparisons"]:
        eligible = comparison["eligible_decisions"]
        agreements = comparison["agreements"]
        disagreements = comparison["disagreements"]
        if agreements + disagreements != eligible:
            raise EvaluationRunError("Baseline comparison counts do not reconcile.")
        if disagreements != len(comparison["disagreement_records"]):
            raise EvaluationRunError("Baseline disagreement count does not match raw records.")
        if comparison["agreement_rate"] != _ratio(agreements, eligible):
            raise EvaluationRunError("Baseline agreement rate does not match raw counts.")

    ablation_ids = [record["id"] for record in result["ablations"]]
    if ablation_ids != [
        "native-simplified-equivalence",
        "network-reachability-context",
        "cloudtrail-incident-correlation",
    ]:
        raise EvaluationRunError("Registered ablation inventory or ordering changed.")
    if result["acceptance"]["passed"] != all(
        check["passed"] for check in result["acceptance"]["checks"]
    ):
        raise EvaluationRunError("Overall acceptance does not match its checks.")
    if result["environment"]["clean_worktree"] is not True:
        raise EvaluationRunError("The recorded primary execution worktree was not clean.")


def _summary_from_result(result: dict[str, Any]) -> EvaluationSummary:
    confusion = result["overall"]["confusion"]
    scores = result["overall"]["scores"]
    return EvaluationSummary(
        scored_assertions=result["counts"]["scored_assertion_count"],
        excluded_assertions=result["counts"]["excluded_assertion_count"],
        true_positive=confusion["true_positive"],
        false_positive=confusion["false_positive"],
        false_negative=confusion["false_negative"],
        true_negative=confusion["true_negative"],
        precision=scores["precision"],
        recall=scores["recall"],
        f1=scores["f1"],
        specificity=scores["specificity"],
        severity_matches=result["counts"]["severity_match_count"],
        matched_positives=result["counts"]["matched_positive_count"],
        acceptance_passed=result["acceptance"]["passed"],
    )


def verify_evaluation_results(
    root: Path = PROJECT_ROOT,
    results_path: Path = RESULTS_PATH,
) -> EvaluationSummary:
    """Re-execute and verify the committed result semantically and byte-for-byte."""

    root = root.resolve(strict=True)
    result_file = results_path if results_path.is_absolute() else root / results_path
    actual = _load_json(result_file, label="Evaluation results")
    schema = _load_json(root / RESULTS_SCHEMA_PATH, label="Evaluation results schema")
    _validate_schema(actual, schema)
    expected = build_evaluation_results(
        root,
        recorded_environment=actual["environment"],
        recorded_evaluated_at=str(actual["evaluated_at"]),
    )
    if actual != expected:
        raise EvaluationRunError(
            "Committed evaluation results differ from deterministic candidate execution."
        )
    if _read_bytes(result_file, label="Evaluation results") != _json_bytes(expected):
        raise EvaluationRunError(
            "Committed evaluation results are not encoded as canonical deterministic JSON."
        )
    _validate_result_invariants(actual)
    return _summary_from_result(actual)


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def write_evaluation_results(root: Path = PROJECT_ROOT) -> EvaluationSummary:
    """Execute the candidate once, validate it, and write the canonical result."""

    root = root.resolve(strict=True)
    if (root / RESULTS_PATH).exists():
        raise EvaluationRunError(
            "The frozen primary result already exists and cannot be overwritten."
        )
    result = build_evaluation_results(root)
    schema = _load_json(root / RESULTS_SCHEMA_PATH, label="Evaluation results schema")
    _validate_schema(result, schema)
    _validate_result_invariants(result)
    _atomic_write(root / RESULTS_PATH, _json_bytes(result))
    return _summary_from_result(result)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute or verify the frozen M12 independent evaluation results."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=PROJECT_ROOT,
        help="Repository root containing the frozen candidate and evaluation artifacts.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Execute the frozen candidate and write the canonical result artifact.",
    )
    return parser


def _format_ratio(value: float | None) -> str:
    return "null" if value is None else f"{value:.4f}"


def main() -> int:
    args = build_parser().parse_args()
    try:
        summary = (
            write_evaluation_results(args.root)
            if args.write
            else verify_evaluation_results(args.root)
        )
    except (OSError, EvaluationRunError, ValueError) as error:
        print(f"Evaluation result verification failed: {error}")
        return 1
    print(
        "Independent evaluation verified: "
        f"{summary.scored_assertions} scored, {summary.excluded_assertions} excluded; "
        f"TP={summary.true_positive}, FP={summary.false_positive}, "
        f"FN={summary.false_negative}, TN={summary.true_negative}; "
        f"precision={_format_ratio(summary.precision)}, "
        f"recall={_format_ratio(summary.recall)}, F1={_format_ratio(summary.f1)}, "
        f"specificity={_format_ratio(summary.specificity)}; "
        f"severity={summary.severity_matches}/{summary.matched_positives}; "
        f"acceptance={'passed' if summary.acceptance_passed else 'failed'}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
