"""Shared finding model and JSON helpers."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "2.0"
LEGACY_SCHEMA_VERSION = "1.0"
SUPPORTED_SCHEMA_VERSIONS = frozenset({LEGACY_SCHEMA_VERSION, SCHEMA_VERSION})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_CONFIDENCE = frozenset({"high", "medium", "low", "unknown"})
ACCOUNT_ID_PATTERN = re.compile(r"^(?:\d{12}|unknown)$")
FINDING_ID_PATTERN = re.compile(r"^FND-[0-9A-F]{32}$")
EVIDENCE_TYPE_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
UTC_TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$"
)
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
LEGACY_FINDING_FIELDS = {
    "severity",
    "references",
    "metadata",
    *REQUIRED_TEXT_FIELDS,
}
V2_FINDING_FIELDS = {
    *LEGACY_FINDING_FIELDS,
    "finding_id",
    "confidence",
    "account_id",
    "region",
    "observed_at",
    "evidence_references",
}


def _require_text(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string.")


def canonicalize_utc_timestamp(
    value: str,
    *,
    field_name: str = "Timestamp",
) -> str:
    """Validate an RFC 3339 UTC timestamp and return its canonical Z form."""

    if not isinstance(value, str) or UTC_TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"{field_name} must use RFC 3339 UTC format ending in Z or +00:00."
        )
    parse_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(parse_value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO 8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use UTC (Z or +00:00).")
    return parsed.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class EvidenceReference:
    """A stable pointer to one source evidence item, not a local file path."""

    type: str
    id: str

    def __post_init__(self) -> None:
        _require_text(self.type, "Evidence reference type")
        if EVIDENCE_TYPE_PATTERN.fullmatch(self.type) is None:
            raise ValueError(
                "Evidence reference type must use lowercase letters, numbers, and hyphens."
            )
        _require_text(self.id, "Evidence reference id")


def _default_evidence_reference(
    module: str,
    resource_type: str,
    resource_id: str,
) -> EvidenceReference:
    return EvidenceReference(
        type="analyzer-input",
        id=f"{module}:{resource_type}/{resource_id}",
    )


def _finding_identity_payload(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "module": finding.module,
        "account_id": finding.account_id,
        "region": finding.region,
        "observed_at": finding.observed_at,
        "resource_type": finding.resource_type,
        "resource_id": finding.resource_id,
        "evidence_references": [
            asdict(reference) for reference in finding.evidence_references
        ],
    }


def _stable_finding_id(finding: Finding) -> str:
    canonical = json.dumps(
        _finding_identity_payload(finding),
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32].upper()
    return f"FND-{digest}"


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
    finding_id: str = ""
    confidence: str = "unknown"
    account_id: str = "unknown"
    region: str = "unknown"
    observed_at: str | None = None
    evidence_references: list[EvidenceReference] = field(default_factory=list)

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
            isinstance(reference, str) and reference.strip()
            for reference in self.references
        ):
            raise ValueError("Finding references must be a list of non-empty strings.")
        if len(self.references) != len(set(self.references)):
            raise ValueError("Finding references must not contain duplicates.")
        if not isinstance(self.metadata, dict) or not all(
            isinstance(key, str)
            and key.strip()
            and isinstance(value, str)
            for key, value in self.metadata.items()
        ):
            raise ValueError(
                "Finding metadata must contain non-empty string keys and string values."
            )

        if not isinstance(self.confidence, str):
            raise ValueError("Finding confidence must be a string.")
        normalized_confidence = self.confidence.lower()
        if normalized_confidence not in VALID_CONFIDENCE:
            allowed = ", ".join(sorted(VALID_CONFIDENCE))
            raise ValueError(f"Finding confidence must be one of: {allowed}.")
        object.__setattr__(self, "confidence", normalized_confidence)

        if not isinstance(self.account_id, str) or ACCOUNT_ID_PATTERN.fullmatch(
            self.account_id
        ) is None:
            raise ValueError(
                "Finding account_id must be a 12-digit AWS account ID or 'unknown'."
            )
        _require_text(self.region, "Finding region")
        object.__setattr__(self, "region", self.region.lower())

        if self.observed_at is not None:
            if not isinstance(self.observed_at, str):
                raise ValueError("Finding observed_at must be a string or null.")
            object.__setattr__(
                self,
                "observed_at",
                canonicalize_utc_timestamp(
                    self.observed_at,
                    field_name="Finding observed_at",
                ),
            )

        evidence_references = self.evidence_references
        if not evidence_references:
            evidence_references = [
                _default_evidence_reference(
                    self.module,
                    self.resource_type,
                    self.resource_id,
                )
            ]
        if not isinstance(evidence_references, list) or not all(
            isinstance(reference, EvidenceReference)
            for reference in evidence_references
        ):
            raise ValueError(
                "Finding evidence_references must contain EvidenceReference objects."
            )
        reference_keys = [
            (reference.type, reference.id) for reference in evidence_references
        ]
        if len(reference_keys) != len(set(reference_keys)):
            raise ValueError("Finding evidence_references must not contain duplicates.")
        sorted_references = sorted(
            evidence_references,
            key=lambda reference: (reference.type, reference.id),
        )
        object.__setattr__(self, "evidence_references", sorted_references)

        expected_id = _stable_finding_id(self)
        if self.finding_id:
            if not isinstance(self.finding_id, str) or FINDING_ID_PATTERN.fullmatch(
                self.finding_id
            ) is None:
                raise ValueError(
                    "Finding finding_id must use FND- followed by 32 uppercase hex characters."
                )
            if self.finding_id != expected_id:
                raise ValueError(
                    "Finding finding_id does not match its stable identity fields."
                )
        else:
            object.__setattr__(self, "finding_id", expected_id)


def with_finding_context(
    finding: Finding,
    *,
    account_id: str | None = None,
    region: str | None = None,
    observed_at: str | None = None,
) -> Finding:
    """Fill missing provenance without overwriting evidence-specific context."""

    resolved_account = (
        account_id
        if account_id is not None and finding.account_id == "unknown"
        else finding.account_id
    )
    resolved_region = (
        region
        if region is not None and finding.region == "unknown"
        else finding.region
    )
    resolved_observed_at = finding.observed_at or observed_at
    if (
        resolved_account == finding.account_id
        and resolved_region == finding.region
        and resolved_observed_at == finding.observed_at
    ):
        return finding
    return replace(
        finding,
        finding_id="",
        account_id=resolved_account,
        region=resolved_region,
        observed_at=resolved_observed_at,
    )


def with_findings_context(
    findings: Iterable[Finding],
    *,
    account_id: str | None = None,
    region: str | None = None,
    observed_at: str | None = None,
) -> list[Finding]:
    """Fill missing provenance for a finding collection."""

    return [
        with_finding_context(
            finding,
            account_id=account_id,
            region=region,
            observed_at=observed_at,
        )
        for finding in findings
    ]


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
            tuple(
                (reference.type, reference.id)
                for reference in item.evidence_references
            ),
            item.finding_id,
        ),
    )


def findings_to_dicts(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    return [asdict(finding) for finding in findings]


def evidence_reference_ids(
    finding: Finding,
    reference_type: str,
) -> list[str]:
    """Return sorted source IDs for one structured evidence-reference type."""

    _require_text(reference_type, "Evidence reference type")
    return sorted(
        {
            reference.id
            for reference in finding.evidence_references
            if reference.type == reference_type
        }
    )


def _evidence_reference_from_dict(data: Any) -> EvidenceReference:
    if not isinstance(data, dict):
        raise ValueError("Each finding evidence reference must be a JSON object.")
    fields = {"type", "id"}
    missing = sorted(fields.difference(data))
    unexpected = sorted(set(data).difference(fields))
    if missing:
        raise ValueError(
            "Finding evidence reference is missing fields: "
            + ", ".join(missing)
            + "."
        )
    if unexpected:
        raise ValueError(
            "Finding evidence reference contains unsupported fields: "
            + ", ".join(unexpected)
            + "."
        )
    return EvidenceReference(type=data["type"], id=data["id"])


def _legacy_evidence_references(data: dict[str, Any]) -> list[EvidenceReference]:
    metadata = data.get("metadata", {})
    if isinstance(metadata, dict):
        event_ids = metadata.get("event_ids") or metadata.get("event_id")
        if isinstance(event_ids, str) and event_ids.strip():
            return [
                EvidenceReference(type="cloudtrail-event", id=event_id.strip())
                for event_id in sorted(set(event_ids.split(",")))
                if event_id.strip()
            ]
    return [
        EvidenceReference(
            type="legacy-finding",
            id=(
                f"{data.get('module', 'unknown')}:"
                f"{data.get('resource_type', 'resource')}/"
                f"{data.get('resource_id', 'unknown')}"
            ),
        )
    ]


def finding_from_dict(
    data: dict[str, Any],
    *,
    schema_version: str = SCHEMA_VERSION,
) -> Finding:
    if not isinstance(data, dict):
        raise ValueError("Each finding must be a JSON object.")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"Unsupported finding schema version {schema_version!r}.")

    expected_fields = (
        LEGACY_FINDING_FIELDS
        if schema_version == LEGACY_SCHEMA_VERSION
        else V2_FINDING_FIELDS
    )
    missing_fields = sorted(expected_fields.difference(data))
    if missing_fields:
        raise ValueError(
            f"Finding is missing required fields: {', '.join(missing_fields)}."
        )
    unexpected_fields = sorted(set(data).difference(expected_fields))
    if unexpected_fields:
        raise ValueError(
            "Finding contains unsupported fields: "
            + ", ".join(unexpected_fields)
            + "."
        )

    references = data["references"]
    metadata = data["metadata"]
    if not isinstance(references, list):
        raise ValueError("Finding references must be a JSON list.")
    if not isinstance(metadata, dict):
        raise ValueError("Finding metadata must be a JSON object.")

    v2_values: dict[str, Any]
    if schema_version == LEGACY_SCHEMA_VERSION:
        v2_values = {
            "finding_id": "",
            "confidence": "unknown",
            "account_id": "unknown",
            "region": "unknown",
            "observed_at": None,
            "evidence_references": _legacy_evidence_references(data),
        }
    else:
        raw_evidence_references = data["evidence_references"]
        if (
            not isinstance(raw_evidence_references, list)
            or not raw_evidence_references
        ):
            raise ValueError(
                "Finding evidence_references must be a non-empty JSON list."
            )
        v2_values = {
            "finding_id": data["finding_id"],
            "confidence": data["confidence"],
            "account_id": data["account_id"],
            "region": data["region"],
            "observed_at": data["observed_at"],
            "evidence_references": [
                _evidence_reference_from_dict(item)
                for item in raw_evidence_references
            ],
        }

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
        **v2_values,
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
    top_level_fields = {"schema_version", "finding_count", "findings"}
    missing_fields = sorted(top_level_fields.difference(payload))
    unexpected_fields = sorted(set(payload).difference(top_level_fields))
    if missing_fields:
        raise ValueError(
            f"{path} is missing fields: {', '.join(missing_fields)}."
        )
    if unexpected_fields:
        raise ValueError(
            f"{path} contains unsupported fields: {', '.join(unexpected_fields)}."
        )

    schema_version = payload["schema_version"]
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(sorted(SUPPORTED_SCHEMA_VERSIONS))
        raise ValueError(
            f"{path} uses unsupported schema version {schema_version!r}; "
            f"supported versions are: {supported}."
        )

    findings = payload["findings"]
    if not isinstance(findings, list):
        raise ValueError(f"{path} must contain a findings list.")

    finding_count = payload["finding_count"]
    if not isinstance(finding_count, int) or isinstance(finding_count, bool):
        raise ValueError(f"{path} must contain an integer finding_count.")
    if finding_count != len(findings):
        raise ValueError(
            f"{path} finding_count is {finding_count}, but the file contains "
            f"{len(findings)} finding(s)."
        )

    return sort_findings(
        finding_from_dict(item, schema_version=schema_version)
        for item in findings
    )
