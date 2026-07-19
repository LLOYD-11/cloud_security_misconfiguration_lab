"""Strict loading, validation, and rendering for the built-in rule catalog."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from cloud_inputs import enforce_collection_limit, load_bounded_json

SCHEMA_VERSION = "1.0"
CATALOG_FILENAME = "rules-v1.0.json"
MODULE_ORDER = ("iam", "storage", "network", "cloudtrail")
VALID_MODULES = frozenset(MODULE_ORDER)
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_CONFIDENCE_LEVELS = frozenset({"high", "medium", "low"})
VALID_RELATIONSHIPS = frozenset({"direct", "related"})
RULE_ID_PATTERN = re.compile(r"^(IAM|STO|NET|CLD)-\d{3}$")
MODULE_PREFIX = {
    "iam": "IAM",
    "storage": "STO",
    "network": "NET",
    "cloudtrail": "CLD",
}


def _require_text(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string.")


def _require_https_url(value: Any, field_name: str) -> None:
    _require_text(value, field_name)
    if not value.startswith("https://"):
        raise ValueError(f"{field_name} must use HTTPS.")


def _check_fields(
    data: Any,
    *,
    label: str,
    required: set[str],
) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError(f"{label} must be a JSON object.")
    missing = sorted(required.difference(data))
    unexpected = sorted(set(data).difference(required))
    if missing:
        raise ValueError(f"{label} is missing fields: {', '.join(missing)}.")
    if unexpected:
        raise ValueError(
            f"{label} contains unsupported fields: {', '.join(unexpected)}."
        )
    return data


@dataclass(frozen=True)
class Framework:
    """One authoritative framework represented by catalog mappings."""

    id: str
    name: str
    version: str
    source_url: str

    def __post_init__(self) -> None:
        for field_name in ("id", "name", "version"):
            _require_text(getattr(self, field_name), f"Framework {field_name}")
        _require_https_url(self.source_url, "Framework source_url")


@dataclass(frozen=True)
class ControlMapping:
    """A qualified relationship between one detector rule and one control."""

    framework: str
    control_id: str
    title: str
    relationship: str
    url: str
    rationale: str

    def __post_init__(self) -> None:
        for field_name in ("framework", "control_id", "title", "rationale"):
            _require_text(
                getattr(self, field_name),
                f"Control mapping {field_name}",
            )
        if self.relationship not in VALID_RELATIONSHIPS:
            allowed = ", ".join(sorted(VALID_RELATIONSHIPS))
            raise ValueError(
                f"Control mapping relationship must be one of: {allowed}."
            )
        _require_https_url(self.url, "Control mapping url")


@dataclass(frozen=True)
class RuleDefinition:
    """Static metadata and framework context for one built-in rule."""

    rule_id: str
    module: str
    title: str
    summary: str
    default_severity: str
    allowed_severities: tuple[str, ...]
    confidence: str
    confidence_basis: str
    mappings: tuple[ControlMapping, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or RULE_ID_PATTERN.fullmatch(
            self.rule_id
        ) is None:
            raise ValueError("Rule rule_id must match IAM/STO/NET/CLD-NNN.")
        if self.module not in VALID_MODULES:
            allowed = ", ".join(MODULE_ORDER)
            raise ValueError(f"Rule module must be one of: {allowed}.")
        if not self.rule_id.startswith(f"{MODULE_PREFIX[self.module]}-"):
            raise ValueError(
                f"Rule {self.rule_id} does not match module {self.module}."
            )
        for field_name in ("title", "summary", "confidence_basis"):
            _require_text(getattr(self, field_name), f"Rule {field_name}")
        if self.default_severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Rule {self.rule_id} has invalid default_severity "
                f"{self.default_severity!r}."
            )
        if (
            not isinstance(self.allowed_severities, tuple)
            or not self.allowed_severities
            or any(
                severity not in VALID_SEVERITIES
                for severity in self.allowed_severities
            )
        ):
            raise ValueError(
                f"Rule {self.rule_id} allowed_severities must contain valid severities."
            )
        if len(self.allowed_severities) != len(set(self.allowed_severities)):
            raise ValueError(
                f"Rule {self.rule_id} allowed_severities must not contain duplicates."
            )
        if self.default_severity not in self.allowed_severities:
            raise ValueError(
                f"Rule {self.rule_id} default_severity must be allowed."
            )
        if self.confidence not in VALID_CONFIDENCE_LEVELS:
            allowed = ", ".join(sorted(VALID_CONFIDENCE_LEVELS))
            raise ValueError(
                f"Rule {self.rule_id} confidence must be one of: {allowed}."
            )
        if not isinstance(self.mappings, tuple) or not self.mappings:
            raise ValueError(f"Rule {self.rule_id} must have at least one mapping.")
        mapping_keys = [
            (item.framework, item.control_id, item.relationship)
            for item in self.mappings
        ]
        if len(mapping_keys) != len(set(mapping_keys)):
            raise ValueError(
                f"Rule {self.rule_id} mappings must not contain duplicates."
            )
        if mapping_keys != sorted(mapping_keys):
            raise ValueError(
                f"Rule {self.rule_id} mappings must use deterministic order."
            )


@dataclass(frozen=True)
class RuleCatalog:
    """A complete, versioned set of built-in detector rules."""

    schema_version: str
    frameworks: tuple[Framework, ...]
    rules: tuple[RuleDefinition, ...]

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported rule catalog schema version {self.schema_version!r}; "
                f"expected {SCHEMA_VERSION!r}."
            )
        if not isinstance(self.frameworks, tuple) or not self.frameworks:
            raise ValueError("Rule catalog frameworks must not be empty.")
        framework_ids = [item.id for item in self.frameworks]
        if len(framework_ids) != len(set(framework_ids)):
            raise ValueError("Rule catalog framework IDs must be unique.")
        if framework_ids != sorted(framework_ids):
            raise ValueError(
                "Rule catalog frameworks must be sorted by framework ID."
            )
        if not isinstance(self.rules, tuple) or not self.rules:
            raise ValueError("Rule catalog rules must not be empty.")
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("Rule catalog rule IDs must be unique.")
        expected_order = sorted(
            self.rules,
            key=lambda rule: (MODULE_ORDER.index(rule.module), rule.rule_id),
        )
        if list(self.rules) != expected_order:
            raise ValueError(
                "Rule catalog rules must use deterministic module and rule ID order."
            )
        known_frameworks = set(framework_ids)
        for rule in self.rules:
            unknown = sorted(
                {
                    mapping.framework
                    for mapping in rule.mappings
                    if mapping.framework not in known_frameworks
                }
            )
            if unknown:
                raise ValueError(
                    f"Rule {rule.rule_id} uses unknown framework(s): "
                    + ", ".join(unknown)
                    + "."
                )

    def get(self, rule_id: str) -> RuleDefinition | None:
        """Return one cataloged rule, or None for a custom rule ID."""

        return next((rule for rule in self.rules if rule.rule_id == rule_id), None)

    def filtered(self, module: str | None = None) -> RuleCatalog:
        """Return a deterministic catalog view for one optional module."""

        if module is None:
            return self
        if module not in VALID_MODULES:
            allowed = ", ".join(MODULE_ORDER)
            raise ValueError(f"Catalog module must be one of: {allowed}.")
        return RuleCatalog(
            schema_version=self.schema_version,
            frameworks=self.frameworks,
            rules=tuple(rule for rule in self.rules if rule.module == module),
        )


def _framework_from_dict(data: Any) -> Framework:
    fields = {"id", "name", "version", "source_url"}
    item = _check_fields(data, label="Framework", required=fields)
    return Framework(**item)


def _mapping_from_dict(data: Any) -> ControlMapping:
    fields = {
        "framework",
        "control_id",
        "title",
        "relationship",
        "url",
        "rationale",
    }
    item = _check_fields(data, label="Control mapping", required=fields)
    return ControlMapping(**item)


def _rule_from_dict(data: Any) -> RuleDefinition:
    fields = {
        "rule_id",
        "module",
        "title",
        "summary",
        "default_severity",
        "allowed_severities",
        "confidence",
        "confidence_basis",
        "mappings",
    }
    item = _check_fields(data, label="Rule", required=fields)
    severities = item["allowed_severities"]
    mappings = item["mappings"]
    if not isinstance(severities, list):
        raise ValueError("Rule allowed_severities must be a JSON list.")
    if not isinstance(mappings, list):
        raise ValueError("Rule mappings must be a JSON list.")
    return RuleDefinition(
        rule_id=item["rule_id"],
        module=item["module"],
        title=item["title"],
        summary=item["summary"],
        default_severity=item["default_severity"],
        allowed_severities=tuple(severities),
        confidence=item["confidence"],
        confidence_basis=item["confidence_basis"],
        mappings=tuple(_mapping_from_dict(mapping) for mapping in mappings),
    )


def rule_catalog_from_dict(data: Any) -> RuleCatalog:
    """Strictly validate and deserialize one versioned rule catalog."""

    item = _check_fields(
        data,
        label="Rule catalog",
        required={"schema_version", "frameworks", "rule_count", "rules"},
    )
    frameworks = item["frameworks"]
    rules = item["rules"]
    if not isinstance(frameworks, list):
        raise ValueError("Rule catalog frameworks must be a JSON list.")
    if not isinstance(rules, list):
        raise ValueError("Rule catalog rules must be a JSON list.")
    rule_count = item["rule_count"]
    if not isinstance(rule_count, int) or isinstance(rule_count, bool):
        raise ValueError("Rule catalog rule_count must be an integer.")
    if rule_count != len(rules):
        raise ValueError(
            f"Rule catalog rule_count is {rule_count}, but it contains "
            f"{len(rules)} rule(s)."
        )
    return RuleCatalog(
        schema_version=item["schema_version"],
        frameworks=tuple(_framework_from_dict(entry) for entry in frameworks),
        rules=tuple(_rule_from_dict(entry) for entry in rules),
    )


def rule_catalog_to_dict(catalog: RuleCatalog) -> dict[str, Any]:
    """Convert a catalog view to its versioned JSON representation."""

    return {
        "schema_version": catalog.schema_version,
        "frameworks": [asdict(framework) for framework in catalog.frameworks],
        "rule_count": len(catalog.rules),
        "rules": [
            {
                **asdict(rule),
                "allowed_severities": list(rule.allowed_severities),
                "mappings": [asdict(mapping) for mapping in rule.mappings],
            }
            for rule in catalog.rules
        ],
    }


def load_rule_catalog_file(path: Path) -> RuleCatalog:
    """Load one rule catalog JSON file from disk."""

    payload = load_bounded_json(
        path,
        label=f"Rule catalog file {path}",
    )
    if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
        enforce_collection_limit(
            len(payload["rules"]),
            label=f"Rule catalog file {path}",
        )
    return rule_catalog_from_dict(payload)


@lru_cache(maxsize=1)
def load_builtin_catalog() -> RuleCatalog:
    """Load the catalog bundled inside the installed Python package."""

    resource = files("cloud_rules").joinpath(CATALOG_FILENAME)
    with resource.open("r", encoding="utf-8") as handle:
        return rule_catalog_from_dict(json.load(handle))


def get_rule(rule_id: str) -> RuleDefinition | None:
    """Return one built-in rule definition."""

    return load_builtin_catalog().get(rule_id)


def validate_rule_emission(
    rule_id: str,
    module: str,
    severity: str,
    *,
    require_known: bool = True,
) -> RuleDefinition | None:
    """Validate finding fields against the static contract for a built-in rule."""

    rule = get_rule(rule_id)
    if rule is None:
        if require_known:
            raise ValueError(f"Rule {rule_id} is not present in the built-in catalog.")
        return None
    if module != rule.module:
        raise ValueError(
            f"Rule {rule_id} belongs to module {rule.module}, not {module}."
        )
    normalized_severity = severity.lower()
    if normalized_severity not in rule.allowed_severities:
        allowed = ", ".join(rule.allowed_severities)
        raise ValueError(
            f"Rule {rule_id} severity {normalized_severity!r} is not allowed; "
            f"expected one of: {allowed}."
        )
    return rule


def _mapping_label(mapping: ControlMapping, frameworks: dict[str, Framework]) -> str:
    framework_name = frameworks[mapping.framework].name
    return f"{framework_name} {mapping.control_id} ({mapping.relationship})"


def render_rule_catalog_markdown(catalog: RuleCatalog) -> str:
    """Render a deterministic, reviewer-friendly rule reference."""

    frameworks = {framework.id: framework for framework in catalog.frameworks}
    lines = [
        "# Detection Rule Catalog",
        "",
        f"Schema version: {catalog.schema_version}",
        "",
        (
            "Confidence describes how directly the available evidence supports the "
            "rule condition. It does not establish malicious intent."
        ),
        "",
        (
            "`direct` means the detector condition substantially matches the control or "
            "technique. `related` means the mapping provides useful context but is not "
            "equivalent coverage."
        ),
        "",
        "## Framework Scope",
        "",
        "| Framework | Version | Source |",
        "| --- | --- | --- |",
    ]
    for framework in catalog.frameworks:
        lines.append(
            f"| {framework.name} | {framework.version} | "
            f"[Authoritative source]({framework.source_url}) |"
        )
    lines.extend(
        [
            "",
            (
                "AWS Security Hub and MITRE ATT&CK mappings track their live public "
                "references. CIS mappings are pinned to the AWS-published v5.0.0 "
                "crosswalk; newer CIS releases are not assigned control IDs by inference."
            ),
        ]
    )

    for module in MODULE_ORDER:
        module_rules = [rule for rule in catalog.rules if rule.module == module]
        if not module_rules:
            continue
        lines.extend(
            [
                "",
                f"## {module.capitalize()}",
                "",
                (
                    "| Rule | Title | Default / Allowed Severity | Confidence | "
                    "Control Mappings |"
                ),
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for rule in module_rules:
            mappings = "<br>".join(
                _mapping_label(mapping, frameworks) for mapping in rule.mappings
            )
            allowed = ", ".join(rule.allowed_severities)
            lines.append(
                f"| `{rule.rule_id}` | {rule.title} | "
                f"{rule.default_severity} / {allowed} | {rule.confidence} | "
                f"{mappings} |"
            )

        for rule in module_rules:
            lines.extend(
                [
                    "",
                    f"### {rule.rule_id}: {rule.title}",
                    "",
                    rule.summary,
                    "",
                    f"Confidence basis: {rule.confidence_basis}",
                    "",
                ]
            )
            for mapping in rule.mappings:
                lines.append(
                    f"- [{_mapping_label(mapping, frameworks)}]({mapping.url}): "
                    f"{mapping.rationale}"
                )

    lines.append("")
    return "\n".join(lines)
