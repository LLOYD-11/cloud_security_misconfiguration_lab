"""Shared finding model and JSON helpers."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "1.0"


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
    return Finding(
        rule_id=str(data["rule_id"]),
        severity=str(data["severity"]),
        module=str(data["module"]),
        category=str(data["category"]),
        resource_type=str(data["resource_type"]),
        resource_id=str(data["resource_id"]),
        title=str(data["title"]),
        evidence=str(data["evidence"]),
        impact=str(data["impact"]),
        remediation=str(data["remediation"]),
        references=[str(item) for item in data.get("references", [])],
        metadata={str(key): str(value) for key, value in data.get("metadata", {}).items()},
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

    if isinstance(payload, list):
        return sort_findings(finding_from_dict(item) for item in payload)

    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object or list.")

    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"{path} must contain a findings list.")

    return sort_findings(finding_from_dict(item) for item in findings)
