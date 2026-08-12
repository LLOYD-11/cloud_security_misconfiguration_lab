"""Validate the frozen M12 holdout corpus without executing an analyzer."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = Path("evaluation/corpus-manifest-v1.0.json")
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_BYTES = 512 * 1024
HASH_BLOCK_BYTES = 64 * 1024
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
AWS_REFERENCE_HOSTS = {"docs.aws.amazon.com"}
SECRET_PATTERNS = (
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"ASIA[0-9A-Z]{16}"),
    re.compile(rb"aws_secret_access_key", re.IGNORECASE),
    re.compile(rb"BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY"),
    re.compile(rb"/Users/"),
)
PROJECT_FIXTURE_LITERALS = (
    b"111122223333",
    b"999988887777",
    b"alice-admin",
    b"public-customer-exports",
    b"internal-audit-logs",
)
REQUIRED_CREDENTIAL_COLUMNS = {
    "user",
    "arn",
    "password_enabled",
    "password_last_used",
    "password_last_changed",
    "mfa_active",
    "access_key_1_active",
    "access_key_1_last_rotated",
    "access_key_1_last_used_date",
    "access_key_2_active",
    "access_key_2_last_rotated",
    "access_key_2_last_used_date",
}
SIMPLIFIED_CONTRACTS = {
    "iam": "schemas/iam-environment-v1.0.schema.json",
    "storage": "schemas/storage-environment-v1.0.schema.json",
    "network": "schemas/network-environment-v1.0.schema.json",
    "cloudtrail": "schemas/cloudtrail-events-v1.0.schema.json",
}
NATIVE_CONTRACTS = {
    "iam": {
        "schemas/aws-iam-authorization-details-v1.0.schema.json",
        "cloud_security_lab/normalizers/iam.py",
    },
    "storage": {"schemas/aws-s3-evidence-bundle-v1.0.schema.json"},
    "network": {"schemas/aws-ec2-describe-security-groups-v1.0.schema.json"},
    "cloudtrail": {"schemas/aws-cloudtrail-records-v1.0.schema.json"},
}


class EvaluationCorpusError(ValueError):
    """Raised when the holdout corpus violates a frozen contract."""


@dataclass(frozen=True)
class CorpusSummary:
    """Verified corpus inventory and pre-execution label counts."""

    case_count: int
    file_count: int
    assertion_count: int
    positive_assertions: int
    negative_assertions: int
    ambiguous_assertions: int
    native_simplified_pairs: int


def _read_regular_file(path: Path, *, limit: int, label: str) -> bytes:
    if path.is_symlink():
        raise EvaluationCorpusError(f"{label} must not be a symlink: {path}.")
    if not path.is_file():
        raise EvaluationCorpusError(f"{label} is not a regular file: {path}.")
    with path.open("rb") as handle:
        content = handle.read(limit + 1)
    if len(content) > limit:
        raise EvaluationCorpusError(
            f"{label} exceeds the {limit:,}-byte verification limit: {path}."
        )
    return content


def _load_json(path: Path, *, limit: int, label: str) -> Any:
    content = _read_regular_file(path, limit=limit, label=label)
    try:
        return json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvaluationCorpusError(f"{label} is not valid UTF-8 JSON: {path}.") from error


def _schema_error_message(error: Any) -> str:
    location = "/".join(str(value) for value in error.absolute_path) or "<root>"
    return f"{location}: {error.message}"


def _validate_schema(instance: Any, schema: Any, *, label: str) -> None:
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        raise EvaluationCorpusError(f"Invalid JSON Schema for {label}: {error}") from error
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(instance),
        key=lambda error: tuple(str(value) for value in error.absolute_path),
    )
    if errors:
        raise EvaluationCorpusError(
            f"{label} violates its JSON Schema: {_schema_error_message(errors[0])}"
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(HASH_BLOCK_BYTES):
            digest.update(block)
    return digest.hexdigest()


def _safe_repository_file(root: Path, raw_path: str) -> Path:
    pure_path = PurePosixPath(raw_path)
    if pure_path.is_absolute() or ".." in pure_path.parts or "." in pure_path.parts:
        raise EvaluationCorpusError(f"Unsafe corpus path: {raw_path!r}.")
    candidate = root.joinpath(*pure_path.parts)
    current = root
    for part in pure_path.parts:
        current = current / part
        if current.is_symlink():
            raise EvaluationCorpusError(f"Corpus path traverses a symlink: {raw_path}.")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise EvaluationCorpusError(
            f"Corpus path cannot be resolved: {raw_path}: {error}"
        ) from error
    root_resolved = root.resolve(strict=True)
    if not resolved.is_relative_to(root_resolved):
        raise EvaluationCorpusError(f"Corpus path escapes the repository: {raw_path}.")
    if not resolved.is_file():
        raise EvaluationCorpusError(f"Corpus path is not a regular file: {raw_path}.")
    return resolved


def _actual_corpus_inventory(root: Path) -> set[str]:
    corpus_root = root / "evaluation/corpus-v1.0"
    if corpus_root.is_symlink() or not corpus_root.is_dir():
        raise EvaluationCorpusError(
            "evaluation/corpus-v1.0 must be a real directory, not a symlink."
        )
    inventory: set[str] = set()
    for path in corpus_root.rglob("*"):
        if path.is_symlink():
            raise EvaluationCorpusError(f"Corpus inventory contains a symlink: {path}.")
        if path.is_file():
            inventory.add(path.relative_to(root).as_posix())
    return inventory


def _scan_public_safety(path: Path, content: bytes) -> None:
    for pattern in SECRET_PATTERNS:
        if pattern.search(content):
            raise EvaluationCorpusError(
                f"Corpus file matches forbidden secret or local-path pattern: {path}."
            )
    for literal in PROJECT_FIXTURE_LITERALS:
        if literal in content:
            raise EvaluationCorpusError(
                f"Corpus file reuses a prohibited project-fixture literal: {path}."
            )


def _validate_credential_report(path: Path, content: bytes) -> None:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise EvaluationCorpusError(
            f"Credential-report fixture is not UTF-8: {path}."
        ) from error
    reader = csv.DictReader(io.StringIO(text))
    fields = set(reader.fieldnames or ())
    missing = sorted(REQUIRED_CREDENTIAL_COLUMNS - fields)
    if missing:
        raise EvaluationCorpusError(
            f"Credential-report fixture {path} is missing columns: {', '.join(missing)}."
        )
    for row in reader:
        if None in row:
            raise EvaluationCorpusError(
                f"Credential-report fixture {path} contains extra CSV fields."
            )


def _validate_evidence_contract(
    root: Path,
    record: dict[str, Any],
    *,
    module: str,
    input_form: str,
) -> None:
    raw_path = str(record["path"])
    path = _safe_repository_file(root, raw_path)
    content = _read_regular_file(
        path,
        limit=MAX_EVIDENCE_BYTES,
        label="Corpus evidence",
    )
    _scan_public_safety(path, content)
    if path.stat().st_size != record["size_bytes"]:
        raise EvaluationCorpusError(f"Corpus size mismatch: {raw_path}.")
    if not SHA256_PATTERN.fullmatch(str(record["sha256"])):
        raise EvaluationCorpusError(f"Corpus digest is malformed: {raw_path}.")
    if _sha256(path) != record["sha256"]:
        raise EvaluationCorpusError(f"Corpus SHA-256 mismatch: {raw_path}.")

    contract = str(record["contract"])
    expected_contracts = (
        {SIMPLIFIED_CONTRACTS[module]}
        if input_form == "simplified"
        else NATIVE_CONTRACTS[module]
    )
    if contract not in expected_contracts:
        raise EvaluationCorpusError(
            f"Unexpected {input_form} contract for {module}: {contract}."
        )
    if record["media_type"] == "application/json":
        evidence = _load_json(
            path,
            limit=MAX_EVIDENCE_BYTES,
            label="Corpus JSON evidence",
        )
        schema_path = _safe_repository_file(root, contract)
        schema = _load_json(
            schema_path,
            limit=MAX_EVIDENCE_BYTES,
            label="Evidence JSON Schema",
        )
        _validate_schema(evidence, schema, label=raw_path)
    elif record["media_type"] == "text/csv":
        if contract != "cloud_security_lab/normalizers/iam.py":
            raise EvaluationCorpusError(
                f"CSV evidence has an unexpected contract: {raw_path}."
            )
        _validate_credential_report(path, content)
    else:
        raise EvaluationCorpusError(
            f"Unsupported retained corpus media type: {record['media_type']}."
        )


def _catalog_inventory(root: Path) -> tuple[dict[str, str], dict[str, set[str]]]:
    catalog = _load_json(
        root / "cloud_rules/rules-v1.0.json",
        limit=MAX_EVIDENCE_BYTES,
        label="Rule catalog",
    )
    rule_modules: dict[str, str] = {}
    allowed_severities: dict[str, set[str]] = {}
    for rule in catalog["rules"]:
        rule_id = str(rule["rule_id"])
        rule_modules[rule_id] = str(rule["module"])
        allowed_severities[rule_id] = set(rule["allowed_severities"])
    return rule_modules, allowed_severities


def _protocol_inventory(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    protocol_record = manifest["protocol"]
    protocol_path = _safe_repository_file(root, protocol_record["path"])
    if _sha256(protocol_path) != protocol_record["sha256"]:
        raise EvaluationCorpusError("The corpus references the wrong protocol digest.")
    protocol = _load_json(
        protocol_path,
        limit=MAX_EVIDENCE_BYTES,
        label="Evaluation protocol",
    )
    if protocol["protocol_version"] != protocol_record["version"]:
        raise EvaluationCorpusError("The corpus and protocol versions do not match.")
    if protocol["candidate"]["analyzer_revision"] != manifest["candidate_revision"]:
        raise EvaluationCorpusError("The corpus candidate revision is not the frozen candidate.")
    catalog_record = protocol["candidate"]["rule_catalog"]
    catalog_path = _safe_repository_file(root, catalog_record["path"])
    if _sha256(catalog_path) != catalog_record["sha256"]:
        raise EvaluationCorpusError("The frozen rule-catalog digest does not match.")
    return protocol


def _validate_reviews(case: dict[str, Any], frozen_on: date) -> None:
    provenance = case["provenance"]
    authored_on = date.fromisoformat(provenance["authored_on"])
    if authored_on > frozen_on:
        raise EvaluationCorpusError(
            f"Case {case['id']} was authored after corpus freeze."
        )
    if provenance["candidate_output_seen"] is not False:
        raise EvaluationCorpusError(
            f"Case {case['id']} was exposed to candidate output before freeze."
        )
    provenance_urls = {reference["url"] for reference in provenance["source_references"]}
    for reference in provenance["source_references"]:
        if date.fromisoformat(reference["retrieved_on"]) > frozen_on:
            raise EvaluationCorpusError(
                f"Case {case['id']} cites a source retrieved after freeze."
            )
    for assertion in case["assertions"]:
        review = assertion["review"]
        primary = review["primary"]
        verification = review["verification"]
        if primary["reviewer_id"] == verification["reviewer_id"]:
            raise EvaluationCorpusError(
                f"Assertion {assertion['id']} does not identify separate review passes."
            )
        if primary["candidate_output_seen"] or verification["candidate_output_seen"]:
            raise EvaluationCorpusError(
                f"Assertion {assertion['id']} review saw candidate output."
            )
        for review_pass in (primary, verification):
            reviewed_on = date.fromisoformat(review_pass["reviewed_on"])
            if reviewed_on < authored_on or reviewed_on > frozen_on:
                raise EvaluationCorpusError(
                    f"Assertion {assertion['id']} has a review outside its authoring "
                    "and freeze dates."
                )
        assertion_urls = {
            reference["url"] for reference in assertion["authoritative_references"]
        }
        if not assertion_urls.issubset(provenance_urls):
            raise EvaluationCorpusError(
                f"Case {case['id']} provenance omits an assertion citation."
            )
        for reference in assertion["authoritative_references"]:
            if reference["authority"] != "aws":
                raise EvaluationCorpusError(
                    f"Assertion {assertion['id']} lacks AWS-authoritative grounding."
                )
            if urlsplit(reference["url"]).hostname not in AWS_REFERENCE_HOSTS:
                raise EvaluationCorpusError(
                    f"Assertion {assertion['id']} cites a non-AWS reference host."
                )
            if date.fromisoformat(reference["retrieved_on"]) > frozen_on:
                raise EvaluationCorpusError(
                    f"Assertion {assertion['id']} cites a source retrieved after freeze."
                )


def _validate_semantics(
    root: Path,
    manifest: dict[str, Any],
    protocol: dict[str, Any],
) -> CorpusSummary:
    rule_modules, allowed_severities = _catalog_inventory(root)
    protocol_rules = {
        rule_id
        for module in protocol["candidate"]["modules"]
        for rule_id in module["rule_ids"]
    }
    if set(rule_modules) != protocol_rules:
        raise EvaluationCorpusError("Protocol and catalog rule inventories differ.")

    cases = manifest["cases"]
    if manifest["case_count"] != len(cases):
        raise EvaluationCorpusError("Manifest case_count does not match cases.")
    case_ids: set[str] = set()
    assertion_ids: set[str] = set()
    decision_keys: set[tuple[str, str, str, str]] = set()
    declared_paths: set[str] = set()
    class_counts: Counter[tuple[str, str]] = Counter()
    label_counts: Counter[str] = Counter()
    rule_label_counts: Counter[tuple[str, str]] = Counter()
    pair_counts: Counter[str] = Counter()
    file_count = 0
    frozen_on = date.fromisoformat(manifest["frozen_on"])

    for case in cases:
        case_id = str(case["id"])
        module = str(case["module"])
        if case_id in case_ids:
            raise EvaluationCorpusError(f"Duplicate case ID: {case_id}.")
        case_ids.add(case_id)
        class_counts[(module, str(case["classification"]))] += 1
        _validate_reviews(case, frozen_on)
        case_label_counts: Counter[str] = Counter()

        variant_ids: set[str] = set()
        forms: list[str] = []
        groups: set[str] = set()
        for variant in case["input_variants"]:
            variant_id = str(variant["id"])
            input_form = str(variant["input_form"])
            if variant_id in variant_ids:
                raise EvaluationCorpusError(
                    f"Case {case_id} repeats input variant {variant_id}."
                )
            variant_ids.add(variant_id)
            forms.append(input_form)
            group = variant["equivalence_group"]
            if group is not None:
                groups.add(str(group))
            contracts = {str(record["contract"]) for record in variant["files"]}
            if input_form == "native" and contracts != NATIVE_CONTRACTS[module]:
                raise EvaluationCorpusError(
                    f"Case {case_id} native variant has incomplete contract inventory."
                )
            if input_form == "simplified" and contracts != {
                SIMPLIFIED_CONTRACTS[module]
            }:
                raise EvaluationCorpusError(
                    f"Case {case_id} simplified variant has the wrong contract."
                )
            for record in variant["files"]:
                raw_path = str(record["path"])
                if raw_path in declared_paths:
                    raise EvaluationCorpusError(
                        f"Corpus file is declared more than once: {raw_path}."
                    )
                declared_paths.add(raw_path)
                _validate_evidence_contract(
                    root,
                    record,
                    module=module,
                    input_form=input_form,
                )
                file_count += 1

        if forms.count("simplified") != 1 or forms.count("native") > 1:
            raise EvaluationCorpusError(
                f"Case {case_id} must have one simplified and at most one native variant."
            )
        if "native" in forms:
            if set(forms) != {"native", "simplified"} or len(groups) != 1:
                raise EvaluationCorpusError(
                    f"Case {case_id} has an invalid native/simplified pair."
                )
            expected_group = next(iter(groups))
            if any(
                variant["equivalence_group"] != expected_group
                for variant in case["input_variants"]
            ):
                raise EvaluationCorpusError(
                    f"Case {case_id} pair does not share one equivalence group."
                )
            pair_counts[module] += 1
        elif groups:
            raise EvaluationCorpusError(
                f"Unpaired case {case_id} declares an equivalence group."
            )

        for assertion in case["assertions"]:
            assertion_id = str(assertion["id"])
            rule_id = str(assertion["rule_id"])
            label = str(assertion["label"])
            if assertion_id in assertion_ids:
                raise EvaluationCorpusError(
                    f"Duplicate assertion ID: {assertion_id}."
                )
            assertion_ids.add(assertion_id)
            if rule_modules.get(rule_id) != module:
                raise EvaluationCorpusError(
                    f"Assertion {assertion_id} uses a rule outside {module}."
                )
            decision_key = (
                case_id,
                rule_id,
                str(assertion["resource_type"]),
                str(assertion["resource_id"]),
            )
            if decision_key in decision_keys:
                raise EvaluationCorpusError(
                    f"Duplicate decision key: {decision_key}."
                )
            decision_keys.add(decision_key)
            severity = assertion["expected_severity"]
            if label == "positive" and severity not in allowed_severities[rule_id]:
                raise EvaluationCorpusError(
                    f"Assertion {assertion_id} uses unregistered severity {severity}."
                )
            if label != "positive" and severity is not None:
                raise EvaluationCorpusError(
                    f"Non-positive assertion {assertion_id} declares a severity."
                )
            label_counts[label] += 1
            case_label_counts[label] += 1
            rule_label_counts[(rule_id, label)] += 1

        classification = str(case["classification"])
        if classification == "positive" and not case_label_counts["positive"]:
            raise EvaluationCorpusError(
                f"Positive case {case_id} contains no positive assertion."
            )
        if classification == "hardened-negative" and (
            case_label_counts["positive"]
            or case_label_counts["ambiguous"]
            or case_label_counts["unsupported"]
        ):
            raise EvaluationCorpusError(
                f"Hardened-negative case {case_id} contains a non-negative assertion."
            )
        if classification == "ambiguous" and not case_label_counts["ambiguous"]:
            raise EvaluationCorpusError(
                f"Ambiguous case {case_id} contains no ambiguous assertion."
            )

    minimum_classes = protocol["corpus_design"]["minimum_case_counts_per_module"]
    for module in SIMPLIFIED_CONTRACTS:
        for classification, minimum in minimum_classes.items():
            if class_counts[(module, classification)] < minimum:
                raise EvaluationCorpusError(
                    f"{module} has fewer than {minimum} {classification} cases."
                )
        minimum_pairs = protocol["corpus_design"][
            "minimum_native_simplified_pairs_per_module"
        ]
        if pair_counts[module] < minimum_pairs:
            raise EvaluationCorpusError(
                f"{module} has fewer than {minimum_pairs} native/simplified pairs."
            )

    minimum_labels = protocol["corpus_design"][
        "minimum_scored_assertions_per_rule"
    ]
    for rule_id in sorted(protocol_rules):
        for label, minimum in minimum_labels.items():
            if rule_label_counts[(rule_id, label)] < minimum:
                raise EvaluationCorpusError(
                    f"{rule_id} has fewer than {minimum} {label} assertions."
                )

    if manifest["file_count"] != file_count:
        raise EvaluationCorpusError("Manifest file_count does not match declarations.")
    actual_paths = _actual_corpus_inventory(root)
    if declared_paths != actual_paths:
        missing = sorted(declared_paths - actual_paths)
        undeclared = sorted(actual_paths - declared_paths)
        raise EvaluationCorpusError(
            "Corpus inventory mismatch; "
            f"missing={missing or 'none'}, undeclared={undeclared or 'none'}."
        )

    return CorpusSummary(
        case_count=len(cases),
        file_count=file_count,
        assertion_count=sum(label_counts.values()),
        positive_assertions=label_counts["positive"],
        negative_assertions=label_counts["negative"],
        ambiguous_assertions=label_counts["ambiguous"],
        native_simplified_pairs=sum(pair_counts.values()),
    )


def verify_corpus(
    root: Path = PROJECT_ROOT,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> CorpusSummary:
    """Verify schemas, provenance, labels, pairs, hashes, and exact inventory."""

    root = root.resolve(strict=True)
    manifest_file = (
        manifest_path
        if manifest_path.is_absolute()
        else root / manifest_path
    )
    manifest_content = _read_regular_file(
        manifest_file,
        limit=MAX_MANIFEST_BYTES,
        label="Evaluation corpus manifest",
    )
    _scan_public_safety(manifest_file, manifest_content)
    try:
        manifest = json.loads(manifest_content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvaluationCorpusError(
            f"Evaluation corpus manifest is not valid UTF-8 JSON: {manifest_file}."
        ) from error
    schema = _load_json(
        root / "schemas/evaluation-corpus-manifest-v1.0.schema.json",
        limit=MAX_EVIDENCE_BYTES,
        label="Evaluation corpus JSON Schema",
    )
    _validate_schema(manifest, schema, label="Evaluation corpus manifest")
    protocol = _protocol_inventory(root, manifest)
    return _validate_semantics(root, manifest, protocol)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the frozen M12 evaluation corpus without importing or executing "
            "candidate analyzers."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=PROJECT_ROOT,
        help="Repository root containing evaluation, schemas, and cloud_rules.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="Manifest path, relative to --root unless absolute.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        summary = verify_corpus(args.root, args.manifest)
    except (OSError, EvaluationCorpusError) as error:
        print(f"Evaluation corpus verification failed: {error}")
        return 1
    print(
        "Evaluation corpus verified: "
        f"{summary.case_count} cases, {summary.file_count} files, "
        f"{summary.assertion_count} assertions "
        f"({summary.positive_assertions} positive, "
        f"{summary.negative_assertions} negative, "
        f"{summary.ambiguous_assertions} ambiguous), "
        f"{summary.native_simplified_pairs} native/simplified pairs."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
