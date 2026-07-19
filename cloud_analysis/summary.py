"""Versioned analysis coverage and evidence-quality summaries."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cloud_inputs import JsonBudget, load_bounded_json

SCHEMA_VERSION = "1.0"
VALID_MODULES = frozenset({"iam", "storage", "network", "cloudtrail"})
VALID_INPUT_FORMATS = frozenset({"simplified", "aws"})
VALID_COVERAGE_STATUSES = frozenset({"complete", "partial", "empty"})
CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _non_negative_int(value: Any, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer.")


def _positive_int(value: Any, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer.")


@dataclass(frozen=True)
class ResourceCoverage:
    """Counts showing how many primary resources reached an analyzer."""

    resource_type: str
    discovered_count: int
    evaluated_count: int
    skipped_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.resource_type, str) or not self.resource_type.strip():
            raise ValueError("Resource coverage resource_type must be a non-empty string.")
        for field_name in ("discovered_count", "evaluated_count", "skipped_count"):
            _non_negative_int(
                getattr(self, field_name),
                f"Resource coverage {field_name}",
            )
        if self.discovered_count != self.evaluated_count + self.skipped_count:
            raise ValueError(
                "Resource coverage discovered_count must equal evaluated_count plus skipped_count."
            )


@dataclass(frozen=True)
class SkippedEvidence:
    """Evidence omitted from one or more analysis paths, with its coverage effect."""

    code: str
    evidence_type: str
    reason: str
    count: int
    affects_coverage: bool
    resource_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or CODE_PATTERN.fullmatch(self.code) is None:
            raise ValueError(
                "Skipped evidence code must use uppercase letters, digits, and underscores."
            )
        for field_name in ("evidence_type", "reason"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Skipped evidence {field_name} must be a non-empty string."
                )
        _positive_int(self.count, "Skipped evidence count")
        if not isinstance(self.affects_coverage, bool):
            raise ValueError("Skipped evidence affects_coverage must be a boolean.")
        if not isinstance(self.resource_ids, list) or not all(
            isinstance(resource_id, str) and resource_id.strip()
            for resource_id in self.resource_ids
        ):
            raise ValueError(
                "Skipped evidence resource_ids must be a list of non-empty strings."
            )
        if len(self.resource_ids) != len(set(self.resource_ids)):
            raise ValueError("Skipped evidence resource_ids must not contain duplicates.")
        if len(self.resource_ids) > self.count:
            raise ValueError(
                "Skipped evidence count must not be lower than its resource_ids length."
            )


@dataclass(frozen=True)
class AnalysisSummary:
    """Deterministic coverage summary for one analyzer invocation."""

    module: str
    analyzer_version: str
    input_format: str
    input_file_count: int
    coverage_status: str
    finding_count: int
    incident_count: int
    parameters: dict[str, str] = field(default_factory=dict)
    resource_coverage: list[ResourceCoverage] = field(default_factory=list)
    skipped_evidence: list[SkippedEvidence] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.module not in VALID_MODULES:
            allowed = ", ".join(sorted(VALID_MODULES))
            raise ValueError(f"Analysis summary module must be one of: {allowed}.")
        if (
            not isinstance(self.analyzer_version, str)
            or not self.analyzer_version.strip()
        ):
            raise ValueError("Analysis summary analyzer_version must be non-empty.")
        if self.input_format not in VALID_INPUT_FORMATS:
            allowed = ", ".join(sorted(VALID_INPUT_FORMATS))
            raise ValueError(
                f"Analysis summary input_format must be one of: {allowed}."
            )
        _positive_int(self.input_file_count, "Analysis summary input_file_count")
        if self.coverage_status not in VALID_COVERAGE_STATUSES:
            allowed = ", ".join(sorted(VALID_COVERAGE_STATUSES))
            raise ValueError(
                f"Analysis summary coverage_status must be one of: {allowed}."
            )
        for field_name in ("finding_count", "incident_count"):
            _non_negative_int(
                getattr(self, field_name),
                f"Analysis summary {field_name}",
            )
        if not isinstance(self.parameters, dict) or not all(
            isinstance(key, str)
            and key.strip()
            and isinstance(value, str)
            and value.strip()
            for key, value in self.parameters.items()
        ):
            raise ValueError(
                "Analysis summary parameters must contain non-empty string keys and values."
            )
        if not isinstance(self.resource_coverage, list) or not all(
            isinstance(item, ResourceCoverage) for item in self.resource_coverage
        ):
            raise ValueError(
                "Analysis summary resource_coverage must contain ResourceCoverage objects."
            )
        resource_types = [item.resource_type for item in self.resource_coverage]
        if len(resource_types) != len(set(resource_types)):
            raise ValueError(
                "Analysis summary resource_coverage must not repeat resource types."
            )
        if resource_types != sorted(resource_types):
            raise ValueError(
                "Analysis summary resource_coverage must be sorted by resource_type."
            )
        if not isinstance(self.skipped_evidence, list) or not all(
            isinstance(item, SkippedEvidence) for item in self.skipped_evidence
        ):
            raise ValueError(
                "Analysis summary skipped_evidence must contain SkippedEvidence objects."
            )
        skip_keys = [
            (item.code, item.evidence_type, tuple(item.resource_ids))
            for item in self.skipped_evidence
        ]
        if skip_keys != sorted(skip_keys):
            raise ValueError(
                "Analysis summary skipped_evidence must use deterministic order."
            )
        if not isinstance(self.warnings, list) or not all(
            isinstance(warning, str) and warning.strip() for warning in self.warnings
        ):
            raise ValueError(
                "Analysis summary warnings must be a list of non-empty strings."
            )
        if len(self.warnings) != len(set(self.warnings)):
            raise ValueError("Analysis summary warnings must not contain duplicates.")

        evaluated_count = sum(
            item.evaluated_count for item in self.resource_coverage
        )
        expected_status = (
            "empty"
            if evaluated_count == 0
            else (
                "partial"
                if any(item.affects_coverage for item in self.skipped_evidence)
                else "complete"
            )
        )
        if self.coverage_status != expected_status:
            raise ValueError(
                "Analysis summary coverage_status is inconsistent with evaluated "
                "resources and skipped evidence."
            )


def analysis_summary_to_dict(summary: AnalysisSummary) -> dict[str, Any]:
    """Convert one summary to its versioned JSON representation."""

    payload = {
        "schema_version": SCHEMA_VERSION,
        **asdict(summary),
    }
    payload["parameters"] = dict(sorted(summary.parameters.items()))
    return payload


def _resource_coverage_from_dict(data: Any) -> ResourceCoverage:
    if not isinstance(data, dict):
        raise ValueError("Each resource coverage entry must be a JSON object.")
    required = {
        "resource_type",
        "discovered_count",
        "evaluated_count",
        "skipped_count",
    }
    missing = sorted(required.difference(data))
    unexpected = sorted(set(data).difference(required))
    if missing:
        raise ValueError(
            "Resource coverage entry is missing fields: " + ", ".join(missing) + "."
        )
    if unexpected:
        raise ValueError(
            "Resource coverage entry contains unsupported fields: "
            + ", ".join(unexpected)
            + "."
        )
    return ResourceCoverage(**data)


def _skipped_evidence_from_dict(data: Any) -> SkippedEvidence:
    if not isinstance(data, dict):
        raise ValueError("Each skipped evidence entry must be a JSON object.")
    required = {
        "code",
        "evidence_type",
        "reason",
        "count",
        "affects_coverage",
        "resource_ids",
    }
    missing = sorted(required.difference(data))
    unexpected = sorted(set(data).difference(required))
    if missing:
        raise ValueError(
            "Skipped evidence entry is missing fields: " + ", ".join(missing) + "."
        )
    if unexpected:
        raise ValueError(
            "Skipped evidence entry contains unsupported fields: "
            + ", ".join(unexpected)
            + "."
        )
    return SkippedEvidence(**data)


def analysis_summary_from_dict(data: Any) -> AnalysisSummary:
    """Validate and deserialize one analysis summary object."""

    if not isinstance(data, dict):
        raise ValueError("Analysis summary must be a JSON object.")
    required = {
        "module",
        "analyzer_version",
        "input_format",
        "input_file_count",
        "coverage_status",
        "finding_count",
        "incident_count",
        "parameters",
        "resource_coverage",
        "skipped_evidence",
        "warnings",
    }
    missing = sorted(required.difference(data))
    unexpected = sorted(set(data).difference(required))
    if missing:
        raise ValueError(
            "Analysis summary is missing required fields: " + ", ".join(missing) + "."
        )
    if unexpected:
        raise ValueError(
            "Analysis summary contains unsupported fields: "
            + ", ".join(unexpected)
            + "."
        )
    resource_coverage = data["resource_coverage"]
    skipped_evidence = data["skipped_evidence"]
    warnings = data["warnings"]
    parameters = data["parameters"]
    if not isinstance(parameters, dict):
        raise ValueError("Analysis summary parameters must be a JSON object.")
    if not isinstance(resource_coverage, list):
        raise ValueError("Analysis summary resource_coverage must be a JSON list.")
    if not isinstance(skipped_evidence, list):
        raise ValueError("Analysis summary skipped_evidence must be a JSON list.")
    if not isinstance(warnings, list):
        raise ValueError("Analysis summary warnings must be a JSON list.")
    return AnalysisSummary(
        module=data["module"],
        analyzer_version=data["analyzer_version"],
        input_format=data["input_format"],
        input_file_count=data["input_file_count"],
        coverage_status=data["coverage_status"],
        finding_count=data["finding_count"],
        incident_count=data["incident_count"],
        parameters=dict(parameters),
        resource_coverage=[
            _resource_coverage_from_dict(item) for item in resource_coverage
        ],
        skipped_evidence=[
            _skipped_evidence_from_dict(item) for item in skipped_evidence
        ],
        warnings=list(warnings),
    )


def write_analysis_summary(path: Path, summary: AnalysisSummary) -> None:
    """Write one deterministic, versioned analysis summary."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(analysis_summary_to_dict(summary), handle, indent=2)
        handle.write("\n")


def load_analysis_summary_file(
    path: Path,
    *,
    budget: JsonBudget | None = None,
) -> AnalysisSummary:
    """Load one supported analysis-summary file."""

    payload = load_bounded_json(
        path,
        label=f"Analysis summary file {path}",
        budget=budget,
    )
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a versioned analysis summary object.")
    schema_version = payload.pop("schema_version", None)
    if schema_version != SCHEMA_VERSION:
        raise ValueError(
            f"{path} uses unsupported analysis summary schema version "
            f"{schema_version!r}; expected {SCHEMA_VERSION!r}."
        )
    return analysis_summary_from_dict(payload)
