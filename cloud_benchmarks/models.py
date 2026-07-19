"""Shared benchmark manifest and finding-signature helpers."""

from __future__ import annotations

import json
from collections import Counter
from importlib.resources import files
from pathlib import Path
from typing import Any, Iterable, cast

from cloud_findings import Finding
from cloud_inputs import load_bounded_json

BENCHMARK_SCHEMA_VERSION = "1.0"
BENCHMARK_MANIFEST_FILENAME = "benchmark-manifest-v1.0.json"

FindingSignature = tuple[str, str, str, str]


def _declared_object_list(
    payload: dict[str, Any],
    *,
    key: str,
    count_key: str,
) -> list[dict[str, Any]]:
    value = payload.get(key)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, dict) for item in value)
    ):
        raise ValueError(f"Benchmark manifest {key} must be a non-empty object list.")
    declared_count = payload.get(count_key)
    if type(declared_count) is not int or declared_count != len(value):
        raise ValueError(
            f"Benchmark manifest {count_key} must equal the number of {key}."
        )
    return cast(list[dict[str, Any]], value)


def finding_signature_dicts(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    """Return deterministic counted signatures for exact benchmark comparisons."""

    counts: Counter[FindingSignature] = Counter(
        (
            finding.rule_id,
            finding.severity,
            finding.resource_type,
            finding.resource_id,
        )
        for finding in findings
    )
    return [
        {
            "rule_id": rule_id,
            "severity": severity,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "count": count,
        }
        for (rule_id, severity, resource_type, resource_id), count in sorted(
            counts.items()
        )
    ]


def load_benchmark_manifest(path: Path | None = None) -> dict[str, Any]:
    """Load the committed benchmark manifest from source or an installed wheel."""

    if path is None:
        resource = files("cloud_benchmarks").joinpath(BENCHMARK_MANIFEST_FILENAME)
        with resource.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    else:
        payload = load_bounded_json(
            path,
            label=f"Benchmark manifest {path}",
        )
    if not isinstance(payload, dict):
        raise ValueError("Benchmark manifest must contain a JSON object.")
    if payload.get("schema_version") != BENCHMARK_SCHEMA_VERSION:
        raise ValueError(
            "Benchmark manifest uses an unsupported schema version; "
            f"expected {BENCHMARK_SCHEMA_VERSION!r}."
        )
    _declared_object_list(payload, key="cases", count_key="case_count")
    _declared_object_list(
        payload,
        key="scale_cases",
        count_key="scale_case_count",
    )
    rule_coverage = payload.get("rule_coverage")
    rule_count = payload.get("rule_count")
    if (
        not isinstance(rule_coverage, list)
        or not rule_coverage
        or not all(isinstance(item, dict) for item in rule_coverage)
        or type(rule_count) is not int
        or rule_count != len(rule_coverage)
    ):
        raise ValueError(
            "Benchmark manifest rule_count must equal a non-empty "
            "rule_coverage object list."
        )
    if not isinstance(payload.get("acceptance_budgets"), dict):
        raise ValueError("Benchmark manifest must contain acceptance_budgets.")
    return cast(dict[str, Any], payload)
