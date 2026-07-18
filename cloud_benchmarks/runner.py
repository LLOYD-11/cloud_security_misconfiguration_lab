"""Execute the committed functional and scale benchmark contracts."""

from __future__ import annotations

import argparse
import gc
import json
import time
import tracemalloc
from pathlib import Path
from typing import Any, Sequence

from cloud_benchmarks.models import finding_signature_dicts, load_benchmark_manifest
from cloud_benchmarks.profiles import (
    ANALYZERS,
    build_scale_environment,
    run_functional_profile,
    scale_input_count,
)

RESULT_SCHEMA_VERSION = "1.0"


def _functional_result(case: dict[str, Any]) -> dict[str, Any]:
    case_id = str(case["id"])
    profile = str(case["profile"])
    expected_error = case.get("expected_error")
    try:
        findings = run_functional_profile(profile)
    except Exception as exc:  # noqa: BLE001 - exception contract is benchmark data
        if not isinstance(expected_error, dict):
            return {
                "id": case_id,
                "passed": False,
                "message": f"Unexpected {type(exc).__name__}: {exc}",
            }
        expected_type = str(expected_error.get("type"))
        expected_message = str(expected_error.get("message"))
        passed = (
            type(exc).__name__ == expected_type
            and str(exc) == expected_message
        )
        return {
            "id": case_id,
            "passed": passed,
            "message": (
                "Rejected malformed evidence with the expected error."
                if passed
                else (
                    f"Expected {expected_type}: {expected_message}; "
                    f"observed {type(exc).__name__}: {exc}"
                )
            ),
        }

    if isinstance(expected_error, dict):
        return {
            "id": case_id,
            "passed": False,
            "message": "Malformed evidence was unexpectedly accepted.",
        }
    actual = finding_signature_dicts(findings)
    expected = case.get("expected_findings")
    passed = actual == expected
    return {
        "id": case_id,
        "passed": passed,
        "message": (
            "Exact finding signatures matched."
            if passed
            else f"Expected {expected!r}; observed {actual!r}."
        ),
    }


def run_functional_cases(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Execute every committed positive, negative, boundary, and malformed case."""

    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise ValueError("Benchmark manifest cases must be a list.")
    return [_functional_result(case) for case in cases if isinstance(case, dict)]


def _rule_counts(findings: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        rule_id = str(finding.rule_id)
        counts[rule_id] = counts.get(rule_id, 0) + 1
    return dict(sorted(counts.items()))


def _scale_result(case: dict[str, Any]) -> dict[str, Any]:
    case_id = str(case["id"])
    module = str(case["module"])
    expected_input_count = int(case["input_count"])
    expected_finding_count = int(case["expected_finding_count"])
    expected_rule_counts = {
        str(key): int(value)
        for key, value in dict(case["expected_rule_counts"]).items()
    }
    max_peak_memory_bytes = int(case["max_peak_memory_bytes"])
    max_findings_per_input = float(case["max_findings_per_input"])

    environment = build_scale_environment(module, expected_input_count)
    observed_input_count = scale_input_count(module, environment)
    analyzer = ANALYZERS[module]

    gc.collect()
    tracemalloc.start()
    try:
        started = time.perf_counter()
        findings = analyzer(environment)
        elapsed_seconds = time.perf_counter() - started
        _, peak_memory_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    repeated_findings = analyzer(environment)
    finding_count = len(findings)
    rule_counts = _rule_counts(findings)
    amplification = finding_count / observed_input_count
    deterministic = findings == repeated_findings
    failures: list[str] = []
    if observed_input_count != expected_input_count:
        failures.append(
            f"input count {observed_input_count} != {expected_input_count}"
        )
    if finding_count != expected_finding_count:
        failures.append(
            f"finding count {finding_count} != {expected_finding_count}"
        )
    if rule_counts != expected_rule_counts:
        failures.append(
            f"rule counts {rule_counts!r} != {expected_rule_counts!r}"
        )
    if amplification > max_findings_per_input:
        failures.append(
            f"finding amplification {amplification:.6f} > "
            f"{max_findings_per_input:.6f}"
        )
    if peak_memory_bytes > max_peak_memory_bytes:
        failures.append(
            f"peak memory {peak_memory_bytes} > {max_peak_memory_bytes}"
        )
    if not deterministic:
        failures.append("repeated analysis produced different findings")

    return {
        "id": case_id,
        "module": module,
        "size": str(case["size"]),
        "input_count": observed_input_count,
        "finding_count": finding_count,
        "rule_counts": rule_counts,
        "finding_amplification": round(amplification, 6),
        "elapsed_seconds": round(elapsed_seconds, 6),
        "peak_memory_bytes": peak_memory_bytes,
        "deterministic": deterministic,
        "passed": not failures,
        "message": "All scale budgets passed." if not failures else "; ".join(failures),
    }


def run_scale_cases(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Measure every deterministic small and large scale profile."""

    cases = manifest.get("scale_cases")
    if not isinstance(cases, list):
        raise ValueError("Benchmark manifest scale_cases must be a list.")
    return [_scale_result(case) for case in cases if isinstance(case, dict)]


def execute_benchmarks(
    manifest: dict[str, Any],
    *,
    include_scale: bool = True,
) -> dict[str, Any]:
    """Execute the benchmark manifest and return a machine-readable result."""

    functional = run_functional_cases(manifest)
    scale = run_scale_cases(manifest) if include_scale else []
    all_results = [*functional, *scale]
    passed = all(bool(result["passed"]) for result in all_results)
    malformed = [
        result
        for result, case in zip(functional, manifest["cases"], strict=True)
        if case["classification"] == "malformed"
    ]
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "benchmark_manifest_version": str(manifest["schema_version"]),
        "functional_case_count": len(functional),
        "functional_passed_count": sum(
            bool(result["passed"]) for result in functional
        ),
        "malformed_case_count": len(malformed),
        "malformed_rejected_count": sum(
            bool(result["passed"]) for result in malformed
        ),
        "scale_case_count": len(scale),
        "scale_passed_count": sum(bool(result["passed"]) for result in scale),
        "passed": passed,
        "functional_results": functional,
        "scale_results": scale,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run deterministic cloud security benchmark contracts."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Optional benchmark manifest path; defaults to the packaged manifest.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/generated/benchmark_results.json"),
        help="Machine-readable result path.",
    )
    parser.add_argument(
        "--skip-scale",
        action="store_true",
        help="Run only functional cases.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = load_benchmark_manifest(args.manifest)
    result = execute_benchmarks(
        manifest,
        include_scale=not args.skip_scale,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "Functional benchmarks: "
        f"{result['functional_passed_count']}/{result['functional_case_count']}"
    )
    print(
        "Malformed evidence rejection: "
        f"{result['malformed_rejected_count']}/{result['malformed_case_count']}"
    )
    if not args.skip_scale:
        print(
            "Scale benchmarks: "
            f"{result['scale_passed_count']}/{result['scale_case_count']}"
        )
        for scale_result in result["scale_results"]:
            print(
                f"  {scale_result['id']}: "
                f"{scale_result['elapsed_seconds']:.6f}s, "
                f"{scale_result['peak_memory_bytes']} peak bytes"
            )
    print(f"Benchmark results saved to {args.output}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
