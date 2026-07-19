"""Prepare and verify bounded release-integrity evidence."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cloud_inputs import InputLimitError, InputLimits, load_bounded_json

MEBIBYTE = 1024 * 1024
MAX_SBOM_BYTES = 16 * MEBIBYTE
MAX_MANIFEST_BYTES = 64 * 1024
HASH_BLOCK_BYTES = MEBIBYTE
MANIFEST_NAME = "SHA256SUMS"
SPDX_VERSION = "SPDX-2.3"
SPDX_DATA_LICENSE = "CC0-1.0"
SPDX_DOCUMENT_ID = "SPDXRef-DOCUMENT"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
SHA1_PATTERN = re.compile(r"[0-9a-f]{40}")
SAFE_FILENAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
PROJECT_NAME_PATTERN = re.compile(
    r"[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*"
)
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*")
MANIFEST_LINE_PATTERN = re.compile(
    r"(?P<digest>[0-9a-f]{64}) (?P<mode>[ *])"
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._+-]*)"
)
SPDX_LIMITS = InputLimits(
    max_json_file_bytes=MAX_SBOM_BYTES,
    max_total_decoded_bytes=MAX_SBOM_BYTES,
)


class ReleaseEvidenceError(ValueError):
    """Raised when release assets or their integrity evidence are invalid."""


@dataclass(frozen=True)
class ReleaseAssets:
    """The three release artifacts covered by the checksum manifest."""

    wheel: Path
    source_distribution: Path
    sbom: Path

    @property
    def files(self) -> tuple[Path, ...]:
        return tuple(sorted((self.wheel, self.source_distribution, self.sbom)))


def normalize_project_name(value: str) -> str:
    """Return the normalized Python distribution name."""

    return re.sub(r"[-_.]+", "-", value).lower()


def _validate_identity(project_name: str, version: str, license_id: str) -> None:
    if PROJECT_NAME_PATTERN.fullmatch(project_name) is None:
        raise ReleaseEvidenceError(f"Invalid project name: {project_name!r}.")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ReleaseEvidenceError(f"Invalid project version: {version!r}.")
    if not license_id or any(character.isspace() for character in license_id):
        raise ReleaseEvidenceError(f"Invalid SPDX license identifier: {license_id!r}.")


def _resolve_dist_directory(dist: Path) -> Path:
    if dist.is_symlink():
        raise ReleaseEvidenceError(f"Release directory must not be a symlink: {dist}.")
    try:
        resolved = dist.resolve(strict=True)
    except OSError as error:
        raise ReleaseEvidenceError(
            f"Release directory cannot be resolved: {dist}: {error}"
        ) from error
    if not resolved.is_dir():
        raise ReleaseEvidenceError(f"Release path is not a directory: {resolved}.")
    return resolved


def _require_regular_file(path: Path, *, dist: Path, label: str) -> Path:
    if path.parent != dist:
        raise ReleaseEvidenceError(f"{label} must be directly inside {dist}.")
    if path.is_symlink():
        raise ReleaseEvidenceError(f"{label} must not be a symlink: {path.name}.")
    if not path.is_file():
        raise ReleaseEvidenceError(f"{label} is not a regular file: {path.name}.")
    if SAFE_FILENAME_PATTERN.fullmatch(path.name) is None:
        raise ReleaseEvidenceError(f"{label} has an unsafe filename: {path.name!r}.")
    return path


def _discover_one(dist: Path, pattern: str, label: str) -> Path:
    matches = tuple(sorted(dist.glob(pattern)))
    if len(matches) != 1:
        names = ", ".join(path.name for path in matches) or "none"
        raise ReleaseEvidenceError(
            f"Expected exactly one {label} in {dist}; found {len(matches)}: {names}."
        )
    return _require_regular_file(matches[0], dist=dist, label=label)


def _validate_distribution_filenames(
    assets: ReleaseAssets,
    *,
    project_name: str,
    version: str,
) -> None:
    wheel_fields = assets.wheel.name.removesuffix(".whl").split("-")
    if len(wheel_fields) not in {5, 6}:
        raise ReleaseEvidenceError(
            f"Wheel filename does not follow the wheel convention: {assets.wheel.name}."
        )
    if normalize_project_name(wheel_fields[0]) != normalize_project_name(project_name):
        raise ReleaseEvidenceError(
            f"Wheel project name does not match {project_name}: {assets.wheel.name}."
        )
    expected_wheel_version = version.replace("-", "_")
    if wheel_fields[1] != expected_wheel_version:
        raise ReleaseEvidenceError(
            f"Wheel version does not match {version}: {assets.wheel.name}."
        )

    sdist_suffix = f"-{version}.tar.gz"
    if not assets.source_distribution.name.endswith(sdist_suffix):
        raise ReleaseEvidenceError(
            "Source-distribution filename does not match project version "
            f"{version}: {assets.source_distribution.name}."
        )
    sdist_project = assets.source_distribution.name[: -len(sdist_suffix)]
    if normalize_project_name(sdist_project) != normalize_project_name(project_name):
        raise ReleaseEvidenceError(
            "Source-distribution project name does not match "
            f"{project_name}: {assets.source_distribution.name}."
        )

    expected_sbom = f"{project_name}.spdx.json"
    if assets.sbom.name != expected_sbom:
        raise ReleaseEvidenceError(
            f"Expected SBOM filename {expected_sbom}; found {assets.sbom.name}."
        )


def discover_release_assets(
    dist: Path,
    *,
    project_name: str,
    version: str,
    license_id: str,
) -> ReleaseAssets:
    """Discover one exact release asset set and validate its filenames."""

    _validate_identity(project_name, version, license_id)
    resolved = _resolve_dist_directory(dist)
    assets = ReleaseAssets(
        wheel=_discover_one(resolved, "*.whl", "wheel"),
        source_distribution=_discover_one(
            resolved,
            "*.tar.gz",
            "source distribution",
        ),
        sbom=_discover_one(resolved, "*.spdx.json", "SPDX SBOM"),
    )
    _validate_distribution_filenames(
        assets,
        project_name=project_name,
        version=version,
    )
    return assets


def sha256_file(path: Path) -> str:
    """Stream one file into SHA-256."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(HASH_BLOCK_BYTES):
            digest.update(block)
    return digest.hexdigest()


def _read_bounded_text(path: Path, *, max_bytes: int, label: str) -> str:
    if path.is_symlink():
        raise ReleaseEvidenceError(f"{label} must not be a symlink: {path}.")
    with path.open("rb") as handle:
        content = handle.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise ReleaseEvidenceError(
            f"{label} exceeds the size limit of {max_bytes:,} bytes."
        )
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseEvidenceError(f"{label} is not valid UTF-8.") from error


def _manifest_path(dist: Path) -> Path:
    return dist / MANIFEST_NAME


def write_checksum_manifest(assets: ReleaseAssets) -> Path:
    """Write a deterministic shasum-compatible manifest atomically."""

    dist = assets.wheel.parent
    manifest = _manifest_path(dist)
    if manifest.is_symlink():
        raise ReleaseEvidenceError(f"{MANIFEST_NAME} must not be a symlink.")
    lines = [
        f"{sha256_file(path)}  {path.name}\n"
        for path in assets.files
    ]
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{MANIFEST_NAME}.",
            dir=dist,
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.writelines(lines)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, manifest)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
    return manifest


def parse_checksum_manifest(path: Path) -> dict[str, str]:
    """Parse a strict SHA-256 manifest without accepting path-bearing names."""

    text = _read_bounded_text(
        path,
        max_bytes=MAX_MANIFEST_BYTES,
        label=MANIFEST_NAME,
    )
    if not text.endswith("\n"):
        raise ReleaseEvidenceError(f"{MANIFEST_NAME} must end with a newline.")
    records: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = MANIFEST_LINE_PATTERN.fullmatch(line)
        if match is None:
            raise ReleaseEvidenceError(
                f"{MANIFEST_NAME} line {line_number} is malformed."
            )
        name = match.group("name")
        if name in records:
            raise ReleaseEvidenceError(
                f"{MANIFEST_NAME} contains duplicate filename {name}."
            )
        records[name] = match.group("digest")
    if not records:
        raise ReleaseEvidenceError(f"{MANIFEST_NAME} is empty.")
    return records


def _require_mapping(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseEvidenceError(f"{label} must be a JSON object.")
    return value


def _valid_document_namespace(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def _relationship_reaches(
    relationships: list[Any],
    *,
    target_id: str,
) -> bool:
    graph: dict[str, set[str]] = {}
    for value in relationships:
        if not isinstance(value, dict):
            continue
        source = value.get("spdxElementId")
        target = value.get("relatedSpdxElement")
        relationship_type = value.get("relationshipType")
        if (
            isinstance(source, str)
            and isinstance(target, str)
            and relationship_type in {"CONTAINS", "DESCRIBES"}
        ):
            graph.setdefault(source, set()).add(target)

    pending = [SPDX_DOCUMENT_ID]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current == target_id:
            return True
        if current in visited:
            continue
        visited.add(current)
        pending.extend(sorted(graph.get(current, ()), reverse=True))
    return False


def validate_spdx_sbom(
    path: Path,
    *,
    project_name: str,
    version: str,
    license_id: str,
) -> None:
    """Validate the project identity and inventory represented by a Syft SBOM."""

    _validate_identity(project_name, version, license_id)
    if path.is_symlink():
        raise ReleaseEvidenceError(f"SPDX SBOM must not be a symlink: {path}.")
    try:
        raw_document = load_bounded_json(
            path,
            label="release SPDX SBOM",
            limits=SPDX_LIMITS,
        )
    except (InputLimitError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseEvidenceError(f"Invalid release SPDX SBOM: {error}") from error
    document = _require_mapping(raw_document, label="SPDX document")

    expected_fields = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": SPDX_DATA_LICENSE,
        "SPDXID": SPDX_DOCUMENT_ID,
    }
    for field, expected in expected_fields.items():
        if document.get(field) != expected:
            raise ReleaseEvidenceError(
                f"SPDX field {field} must be {expected!r}."
            )
    expected_document_name = f"{project_name}-wheel"
    if document.get("name") != expected_document_name:
        raise ReleaseEvidenceError(
            f"SPDX document name must be {expected_document_name!r}."
        )
    if not _valid_document_namespace(document.get("documentNamespace")):
        raise ReleaseEvidenceError(
            "SPDX documentNamespace must be an absolute HTTPS URL."
        )

    creation_info = _require_mapping(
        document.get("creationInfo"),
        label="SPDX creationInfo",
    )
    creators = creation_info.get("creators")
    if (
        not isinstance(creators, list)
        or not creators
        or not all(isinstance(value, str) and value for value in creators)
    ):
        raise ReleaseEvidenceError("SPDX creationInfo.creators must be non-empty.")
    if not isinstance(creation_info.get("created"), str):
        raise ReleaseEvidenceError("SPDX creationInfo.created must be a string.")

    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ReleaseEvidenceError("SPDX packages must be a non-empty array.")
    normalized_expected = normalize_project_name(project_name)
    source_packages = [
        value
        for value in packages
        if isinstance(value, dict)
        and value.get("name") == expected_document_name
    ]
    if (
        len(source_packages) != 1
        or source_packages[0].get("versionInfo") != version
        or source_packages[0].get("filesAnalyzed") is not False
    ):
        raise ReleaseEvidenceError(
            "SPDX must contain one non-file-analyzed wheel source package "
            f"named {expected_document_name!r} at version {version!r}."
        )
    project_packages = [
        value
        for value in packages
        if isinstance(value, dict)
        and isinstance(value.get("name"), str)
        and normalize_project_name(value["name"]) == normalized_expected
    ]
    if len(project_packages) != 1:
        raise ReleaseEvidenceError(
            "SPDX must contain exactly one package for "
            f"{project_name}; found {len(project_packages)}."
        )
    package = project_packages[0]
    if package.get("versionInfo") != version:
        raise ReleaseEvidenceError(
            f"SPDX package version must be {version!r}."
        )
    if package.get("licenseDeclared") != license_id:
        raise ReleaseEvidenceError(
            f"SPDX package licenseDeclared must be {license_id!r}."
        )
    if package.get("filesAnalyzed") is not True:
        raise ReleaseEvidenceError(
            "SPDX project package must inventory analyzed wheel files."
        )

    package_id = package.get("SPDXID")
    if not isinstance(package_id, str) or not package_id.startswith("SPDXRef-"):
        raise ReleaseEvidenceError("SPDX project package has an invalid SPDXID.")
    verification_code = package.get("packageVerificationCode")
    if not isinstance(verification_code, dict) or SHA1_PATTERN.fullmatch(
        str(verification_code.get("packageVerificationCodeValue", ""))
    ) is None:
        raise ReleaseEvidenceError(
            "SPDX project package must contain a valid package verification code."
        )

    expected_purl = f"pkg:pypi/{normalized_expected}@{version}"
    external_refs = package.get("externalRefs")
    if not isinstance(external_refs, list) or not any(
        isinstance(value, dict)
        and value.get("referenceCategory") == "PACKAGE-MANAGER"
        and value.get("referenceType") == "purl"
        and value.get("referenceLocator") == expected_purl
        for value in external_refs
    ):
        raise ReleaseEvidenceError(
            f"SPDX project package must contain PyPI purl {expected_purl!r}."
        )

    files = document.get("files")
    if not isinstance(files, list) or not files:
        raise ReleaseEvidenceError("SPDX must contain the analyzed wheel file inventory.")
    relationships = document.get("relationships")
    if not isinstance(relationships, list) or not _relationship_reaches(
        relationships,
        target_id=package_id,
    ):
        raise ReleaseEvidenceError(
            "SPDX document does not describe or contain the project package."
        )


def verify_release_evidence(
    dist: Path,
    *,
    project_name: str,
    version: str,
    license_id: str,
) -> ReleaseAssets:
    """Verify asset identity, SPDX content, manifest inventory, and digests."""

    assets = discover_release_assets(
        dist,
        project_name=project_name,
        version=version,
        license_id=license_id,
    )
    validate_spdx_sbom(
        assets.sbom,
        project_name=project_name,
        version=version,
        license_id=license_id,
    )
    manifest = _manifest_path(assets.wheel.parent)
    _require_regular_file(manifest, dist=assets.wheel.parent, label=MANIFEST_NAME)
    records = parse_checksum_manifest(manifest)
    expected_names = {path.name for path in assets.files}
    if set(records) != expected_names:
        missing = sorted(expected_names - set(records))
        unexpected = sorted(set(records) - expected_names)
        raise ReleaseEvidenceError(
            f"{MANIFEST_NAME} inventory mismatch; "
            f"missing={missing}, unexpected={unexpected}."
        )
    for path in assets.files:
        actual = sha256_file(path)
        if not hmac.compare_digest(records[path.name], actual):
            raise ReleaseEvidenceError(
                f"SHA-256 mismatch for release artifact {path.name}."
            )
    return assets


def prepare_release_evidence(
    dist: Path,
    *,
    project_name: str,
    version: str,
    license_id: str,
) -> ReleaseAssets:
    """Validate assets, write SHA256SUMS, and immediately verify the result."""

    assets = discover_release_assets(
        dist,
        project_name=project_name,
        version=version,
        license_id=license_id,
    )
    validate_spdx_sbom(
        assets.sbom,
        project_name=project_name,
        version=version,
        license_id=license_id,
    )
    write_checksum_manifest(assets)
    return verify_release_evidence(
        dist,
        project_name=project_name,
        version=version,
        license_id=license_id,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare or verify release checksums and SPDX identity.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--dist", type=Path, required=True)
        subparser.add_argument("--project-name", required=True)
        subparser.add_argument("--version", required=True)
        subparser.add_argument("--license-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the release-evidence command."""

    arguments = _parser().parse_args(argv)
    operation = (
        prepare_release_evidence
        if arguments.command == "prepare"
        else verify_release_evidence
    )
    try:
        assets = operation(
            arguments.dist,
            project_name=arguments.project_name,
            version=arguments.version,
            license_id=arguments.license_id,
        )
    except (OSError, ReleaseEvidenceError) as error:
        print(f"Release evidence error: {error}", file=sys.stderr)
        return 2
    print(
        f"{arguments.command.capitalize()}d release evidence for "
        f"{len(assets.files)} artifacts in {assets.wheel.parent}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
