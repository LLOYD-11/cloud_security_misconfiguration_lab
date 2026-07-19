"""Enforce independent statement and branch coverage budgets."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Sequence, cast

from cloud_benchmarks.models import load_benchmark_manifest
from cloud_inputs import load_bounded_json


def _percentage(numerator: int, denominator: int, label: str) -> float:
    if denominator <= 0:
        raise ValueError(f"Coverage report {label} denominator must be positive.")
    return 100.0 * numerator / denominator


def _coverage_minima(manifest: dict[str, Any]) -> tuple[float, float]:
    budgets_value = manifest.get("acceptance_budgets")
    if not isinstance(budgets_value, dict):
        raise ValueError("Benchmark manifest must contain acceptance_budgets.")
    budgets = cast(dict[str, Any], budgets_value)
    return (
        float(budgets["minimum_statement_coverage_percent"]),
        float(budgets["minimum_branch_coverage_percent"]),
    )


def evaluate_coverage(
    coverage_payload: dict[str, Any],
    manifest: dict[str, Any],
) -> tuple[float, float, list[str]]:
    """Return statement/branch percentages and any budget failures."""

    totals_value = coverage_payload.get("totals")
    if not isinstance(totals_value, dict):
        raise ValueError("Coverage JSON must contain a totals object.")
    totals = cast(dict[str, Any], totals_value)

    statement_percent = _percentage(
        int(totals["covered_lines"]),
        int(totals["num_statements"]),
        "statement",
    )
    branch_percent = _percentage(
        int(totals["covered_branches"]),
        int(totals["num_branches"]),
        "branch",
    )
    minimum_statement, minimum_branch = _coverage_minima(manifest)
    failures: list[str] = []
    if statement_percent < minimum_statement:
        failures.append(
            f"statement coverage {statement_percent:.2f}% is below "
            f"{minimum_statement:.2f}%"
        )
    if branch_percent < minimum_branch:
        failures.append(
            f"branch coverage {branch_percent:.2f}% is below "
            f"{minimum_branch:.2f}%"
        )
    return statement_percent, branch_percent, failures


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Enforce separate statement and branch coverage budgets."
    )
    parser.add_argument("coverage_json", type=Path)
    parser.add_argument("--manifest", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = load_bounded_json(
        args.coverage_json,
        label=f"Coverage JSON {args.coverage_json}",
    )
    if not isinstance(payload, dict):
        raise ValueError("Coverage JSON must contain an object.")
    manifest = load_benchmark_manifest(args.manifest)
    statement_percent, branch_percent, failures = evaluate_coverage(
        cast(dict[str, Any], payload),
        manifest,
    )
    minimum_statement, minimum_branch = _coverage_minima(manifest)
    print(
        f"Statement coverage: {statement_percent:.2f}% "
        f"(minimum {minimum_statement:.2f}%)"
    )
    print(
        f"Branch coverage: {branch_percent:.2f}% "
        f"(minimum {minimum_branch:.2f}%)"
    )
    for failure in failures:
        print(f"Coverage failure: {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
