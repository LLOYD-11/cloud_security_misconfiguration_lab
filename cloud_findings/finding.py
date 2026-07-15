"""Shared finding model and JSON helpers."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "1.0"
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
REQUIRED_TEXT_FIELDS = (
    "rule_id",
    "module",
    "category",
    "resource_type",
    "resource_id",
    "title",
    "evidence",
    "impact",
    "remediation",
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    module: str
    category: str
    resource_type: str
    resource_id: str
    title: str
    evidence: str
    impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.severity, str) or not self.severity.strip():
            raise ValueError("Finding severity must be a non-empty string.")
        normalized_severity = self.severity.lower()
        if normalized_severity not in VALID_SEVERITIES:
            allowed = ", ".join(sorted(VALID_SEVERITIES))
            raise ValueError(f"Finding severity must be one of: {allowed}.")
        object.__setattr__(self, "severity", normalized_severity)

        for field_name in REQUIRED_TEXT_FIELDS:
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Finding {field_name} must be a non-empty string.")

        if not isinstance(self.references, list) or not all(
            isinstance(reference, str) for reference in self.references
        ):
            raise ValueError("Finding references must be a list of strings.")
        if not isinstance(self.metadata, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in self.metadata.items()
        ):
            raise ValueError("Finding metadata must contain string keys and values.")


def severity_rank(severity: str) -> int:
    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    return order.get(severity.lower(), 5)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            severity_rank(item.severity),
            item.module,
            item.rule_id,
            item.resource_type,
            item.resource_id,
        ),
    )


def findings_to_dicts(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    return [asdict(finding) for finding in findings]


def finding_from_dict(data: dict[str, Any]) -> Finding:
    if not isinstance(data, dict):
        raise ValueError("Each finding must be a JSON object.")

    required_fields = {"severity", *REQUIRED_TEXT_FIELDS}
    missing_fields = sorted(required_fields.difference(data))
    if missing_fields:
        raise ValueError(f"Finding is missing required fields: {', '.join(missing_fields)}.")

    references = data.get("references", [])
    metadata = data.get("metadata", {})
    if not isinstance(references, list):
        raise ValueError("Finding references must be a JSON list.")
    if not isinstance(metadata, dict):
        raise ValueError("Finding metadata must be a JSON object.")

    return Finding(
        rule_id=data["rule_id"],
        severity=data["severity"],
        module=data["module"],
        category=data["category"],
        resource_type=data["resource_type"],
        resource_id=data["resource_id"],
        title=data["title"],
        evidence=data["evidence"],
        impact=data["impact"],
        remediation=data["remediation"],
        references=list(references),
        metadata=dict(metadata),
    )


def write_findings(path: Path, findings: Iterable[Finding]) -> None:
    sorted_findings = sort_findings(findings)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "finding_count": len(sorted_findings),
        "findings": findings_to_dicts(sorted_findings),
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def load_findings_file(path: Path) -> list[Finding]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a versioned findings JSON object.")

    schema_version = payload.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise ValueError(
            f"{path} uses unsupported schema version {schema_version!r}; "
            f"expected {SCHEMA_VERSION!r}."
        )

    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"{path} must contain a findings list.")

    finding_count = payload.get("finding_count")
    if not isinstance(finding_count, int) or isinstance(finding_count, bool):
        raise ValueError(f"{path} must contain an integer finding_count.")
    if finding_count != len(findings):
        raise ValueError(
            f"{path} finding_count is {finding_count}, but the file contains "
            f"{len(findings)} finding(s)."
        )

    return sort_findings(finding_from_dict(item) for item in findings)
