import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tools.release_evidence import (
    MANIFEST_NAME,
    MAX_MANIFEST_BYTES,
    ReleaseEvidenceError,
    discover_release_assets,
    main,
    normalize_project_name,
    prepare_release_evidence,
    sha256_file,
    validate_spdx_sbom,
    verify_release_evidence,
)

PROJECT_NAME = "cloud-security-misconfiguration-lab"
VERSION = "2.2.0"
LICENSE_ID = "MIT"
WHEEL_NAME = "cloud_security_misconfiguration_lab-2.2.0-py3-none-any.whl"
SDIST_NAME = "cloud_security_misconfiguration_lab-2.2.0.tar.gz"
SBOM_NAME = f"{PROJECT_NAME}.spdx.json"
PACKAGE_ID = "SPDXRef-Package-python-cloud-security-misconfiguration-lab"
ROOT_ID = "SPDXRef-DocumentRoot"


def _spdx_document() -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{PROJECT_NAME}-wheel",
        "documentNamespace": "https://example.com/spdx/cloud-security/2.2.0",
        "creationInfo": {
            "created": "2026-07-19T00:00:00Z",
            "creators": ["Tool: syft-1.48.0"],
        },
        "packages": [
            {
                "name": PROJECT_NAME,
                "SPDXID": PACKAGE_ID,
                "versionInfo": VERSION,
                "filesAnalyzed": True,
                "packageVerificationCode": {
                    "packageVerificationCodeValue": "a" * 40,
                },
                "licenseDeclared": LICENSE_ID,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": (
                            "pkg:pypi/cloud-security-misconfiguration-lab@2.2.0"
                        ),
                    }
                ],
            },
            {
                "name": f"{PROJECT_NAME}-wheel",
                "SPDXID": ROOT_ID,
                "versionInfo": VERSION,
                "filesAnalyzed": False,
            },
        ],
        "files": [
            {
                "fileName": "cloud_security_lab/__init__.py",
                "SPDXID": "SPDXRef-File-package-init",
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": "b" * 64,
                    }
                ],
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": ROOT_ID,
                "relationshipType": "DESCRIBES",
            },
            {
                "spdxElementId": ROOT_ID,
                "relatedSpdxElement": PACKAGE_ID,
                "relationshipType": "CONTAINS",
            },
        ],
    }


def _write_asset_set(root: Path, document: object | None = None) -> None:
    (root / WHEEL_NAME).write_bytes(b"wheel payload\n")
    (root / SDIST_NAME).write_bytes(b"source payload\n")
    (root / SBOM_NAME).write_text(
        json.dumps(_spdx_document() if document is None else document),
        encoding="utf-8",
    )


def _prepare(root: Path):
    return prepare_release_evidence(
        root,
        project_name=PROJECT_NAME,
        version=VERSION,
        license_id=LICENSE_ID,
    )


def _verify(root: Path):
    return verify_release_evidence(
        root,
        project_name=PROJECT_NAME,
        version=VERSION,
        license_id=LICENSE_ID,
    )


class ReleaseEvidenceTests(unittest.TestCase):
    def test_prepare_writes_sorted_shasum_manifest_and_verifies(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)

            assets = _prepare(root)
            manifest = (root / MANIFEST_NAME).read_text(encoding="utf-8")
            verified = _verify(root)

        lines = manifest.splitlines()
        expected_names = sorted(path.name for path in assets.files)
        self.assertEqual(expected_names, [path.name for path in verified.files])
        self.assertEqual(expected_names, [line.split("  ", 1)[1] for line in lines])
        self.assertTrue(all(len(line.split("  ", 1)[0]) == 64 for line in lines))
        self.assertEqual(3, len(lines))

    def test_tampered_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            _prepare(root)
            (root / WHEEL_NAME).write_bytes(b"tampered\n")

            with self.assertRaisesRegex(
                ReleaseEvidenceError,
                "SHA-256 mismatch",
            ):
                _verify(root)

    def test_manifest_rejects_malformed_duplicate_and_unsafe_records(self):
        invalid_manifests = (
            f"{'a' * 63}  {WHEEL_NAME}\n",
            f"{'a' * 64}  ../{WHEEL_NAME}\n",
            f"{'a' * 64}  {WHEEL_NAME}\n{'b' * 64}  {WHEEL_NAME}\n",
            f"{'a' * 64}  {WHEEL_NAME}",
            "\n",
        )
        for manifest in invalid_manifests:
            with self.subTest(manifest=manifest[:80]), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                _write_asset_set(root)
                _prepare(root)
                (root / MANIFEST_NAME).write_text(manifest, encoding="utf-8")

                with self.assertRaises(ReleaseEvidenceError):
                    _verify(root)

    def test_manifest_inventory_must_exactly_cover_release_assets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            assets = _prepare(root)
            first = assets.files[0]
            (root / MANIFEST_NAME).write_text(
                f"{sha256_file(first)}  {first.name}\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ReleaseEvidenceError,
                "inventory mismatch",
            ):
                _verify(root)

    def test_discovery_rejects_duplicate_missing_and_non_file_assets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            (root / "other-2.2.0-py3-none-any.whl").write_bytes(b"other")
            with self.assertRaisesRegex(
                ReleaseEvidenceError,
                "exactly one wheel",
            ):
                discover_release_assets(
                    root,
                    project_name=PROJECT_NAME,
                    version=VERSION,
                    license_id=LICENSE_ID,
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            (root / SDIST_NAME).unlink()
            with self.assertRaisesRegex(
                ReleaseEvidenceError,
                "source distribution",
            ):
                discover_release_assets(
                    root,
                    project_name=PROJECT_NAME,
                    version=VERSION,
                    license_id=LICENSE_ID,
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            (root / SBOM_NAME).unlink()
            (root / SBOM_NAME).mkdir()
            with self.assertRaisesRegex(
                ReleaseEvidenceError,
                "regular file",
            ):
                discover_release_assets(
                    root,
                    project_name=PROJECT_NAME,
                    version=VERSION,
                    license_id=LICENSE_ID,
                )

    def test_discovery_rejects_symlinks_and_identity_mismatches(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            external = root / "external.json"
            external.write_text("{}", encoding="utf-8")
            (root / SBOM_NAME).unlink()
            (root / SBOM_NAME).symlink_to(external)

            with self.assertRaisesRegex(ReleaseEvidenceError, "symlink"):
                discover_release_assets(
                    root,
                    project_name=PROJECT_NAME,
                    version=VERSION,
                    license_id=LICENSE_ID,
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            with self.assertRaisesRegex(ReleaseEvidenceError, "Wheel version"):
                discover_release_assets(
                    root,
                    project_name=PROJECT_NAME,
                    version="2.2.1",
                    license_id=LICENSE_ID,
                )

    def test_spdx_requires_exact_identity_inventory_and_relationships(self):
        mutations = (
            ("spdxVersion", lambda value: value.__setitem__("spdxVersion", "SPDX-2.2")),
            (
                "package version",
                lambda value: value["packages"][0].__setitem__("versionInfo", "9.9.9"),
            ),
            (
                "license",
                lambda value: value["packages"][0].__setitem__(
                    "licenseDeclared",
                    "NOASSERTION",
                ),
            ),
            (
                "files analyzed",
                lambda value: value["packages"][0].__setitem__("filesAnalyzed", False),
            ),
            (
                "purl",
                lambda value: value["packages"][0].__setitem__("externalRefs", []),
            ),
            ("file inventory", lambda value: value.__setitem__("files", [])),
            (
                "relationship",
                lambda value: value.__setitem__("relationships", []),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                document = copy.deepcopy(_spdx_document())
                mutate(document)
                _write_asset_set(root, document)

                with self.assertRaises(ReleaseEvidenceError):
                    validate_spdx_sbom(
                        root / SBOM_NAME,
                        project_name=PROJECT_NAME,
                        version=VERSION,
                        license_id=LICENSE_ID,
                    )

    def test_spdx_rejects_invalid_document_metadata_and_duplicate_project(self):
        mutations = (
            lambda value: value.__setitem__("documentNamespace", "relative"),
            lambda value: value.__setitem__("creationInfo", []),
            lambda value: value["creationInfo"].__setitem__("creators", []),
            lambda value: value["packages"].append(
                copy.deepcopy(value["packages"][0])
            ),
            lambda value: value["packages"][0].__setitem__(
                "packageVerificationCode",
                {},
            ),
        )
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                document = copy.deepcopy(_spdx_document())
                mutate(document)
                _write_asset_set(root, document)
                with self.assertRaises(ReleaseEvidenceError):
                    validate_spdx_sbom(
                        root / SBOM_NAME,
                        project_name=PROJECT_NAME,
                        version=VERSION,
                        license_id=LICENSE_ID,
                    )

    def test_cli_prepares_verifies_and_reports_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            common = [
                "--dist",
                str(root),
                "--project-name",
                PROJECT_NAME,
                "--version",
                VERSION,
                "--license-id",
                LICENSE_ID,
            ]
            output = io.StringIO()
            with redirect_stdout(output):
                prepare_status = main(["prepare", *common])
                verify_status = main(["verify", *common])

            (root / WHEEL_NAME).unlink()
            error = io.StringIO()
            with redirect_stderr(error):
                error_status = main(["verify", *common])

        self.assertEqual(0, prepare_status)
        self.assertEqual(0, verify_status)
        self.assertEqual(2, error_status)
        self.assertIn("3 artifacts", output.getvalue())
        self.assertIn("Release evidence error", error.getvalue())

    def test_project_name_normalization_and_invalid_cli_identity(self):
        self.assertEqual(
            "cloud-security-misconfiguration-lab",
            normalize_project_name("Cloud_Security.Misconfiguration-Lab"),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            with self.assertRaisesRegex(ReleaseEvidenceError, "Invalid project name"):
                discover_release_assets(
                    root,
                    project_name="../escape",
                    version=VERSION,
                    license_id=LICENSE_ID,
                )

    def test_identity_and_release_directory_boundaries(self):
        invalid_identities = (
            ("bad/name", VERSION, LICENSE_ID, "project name"),
            (PROJECT_NAME, "2.2 0", LICENSE_ID, "version"),
            (PROJECT_NAME, VERSION, "MIT OR Apache", "license"),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            for project_name, version, license_id, message in invalid_identities:
                with self.subTest(message=message), self.assertRaisesRegex(
                    ReleaseEvidenceError,
                    message,
                ):
                    discover_release_assets(
                        root,
                        project_name=project_name,
                        version=version,
                        license_id=license_id,
                    )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            file_path = root / "not-a-directory"
            file_path.write_text("data", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseEvidenceError, "not a directory"):
                discover_release_assets(
                    file_path,
                    project_name=PROJECT_NAME,
                    version=VERSION,
                    license_id=LICENSE_ID,
                )

            real_dist = root / "real-dist"
            real_dist.mkdir()
            linked_dist = root / "linked-dist"
            linked_dist.symlink_to(real_dist, target_is_directory=True)
            with self.assertRaisesRegex(ReleaseEvidenceError, "directory.*symlink"):
                discover_release_assets(
                    linked_dist,
                    project_name=PROJECT_NAME,
                    version=VERSION,
                    license_id=LICENSE_ID,
                )

    def test_distribution_filename_boundaries(self):
        replacements = (
            (WHEEL_NAME, "bad.whl", "wheel convention"),
            (
                WHEEL_NAME,
                "another_project-2.2.0-py3-none-any.whl",
                "Wheel project name",
            ),
            (
                SDIST_NAME,
                "another_project-2.2.0.tar.gz",
                "Source-distribution project name",
            ),
            (
                SDIST_NAME,
                "cloud_security_misconfiguration_lab-9.9.9.tar.gz",
                "Source-distribution filename",
            ),
            (SBOM_NAME, "other.spdx.json", "Expected SBOM filename"),
            (WHEEL_NAME, "unsafe name.whl", "unsafe filename"),
        )
        for original, replacement, message in replacements:
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                _write_asset_set(root)
                (root / original).rename(root / replacement)
                with self.assertRaisesRegex(ReleaseEvidenceError, message):
                    discover_release_assets(
                        root,
                        project_name=PROJECT_NAME,
                        version=VERSION,
                        license_id=LICENSE_ID,
                    )

    def test_manifest_rejects_symlink_oversize_and_non_utf8_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            external = root / "external-manifest"
            external.write_text("unchanged", encoding="utf-8")
            (root / MANIFEST_NAME).symlink_to(external)
            with self.assertRaisesRegex(ReleaseEvidenceError, "must not be a symlink"):
                _prepare(root)
            self.assertEqual("unchanged", external.read_text(encoding="utf-8"))

        invalid_content = (
            (b"\xff\n", "valid UTF-8"),
            (b"x" * (MAX_MANIFEST_BYTES + 1), "size limit"),
        )
        for content, message in invalid_content:
            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                _write_asset_set(root)
                _prepare(root)
                (root / MANIFEST_NAME).write_bytes(content)
                with self.assertRaisesRegex(ReleaseEvidenceError, message):
                    _verify(root)

    def test_spdx_rejects_invalid_json_and_structural_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _write_asset_set(root)
            (root / SBOM_NAME).write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseEvidenceError, "Invalid release SPDX"):
                validate_spdx_sbom(
                    root / SBOM_NAME,
                    project_name=PROJECT_NAME,
                    version=VERSION,
                    license_id=LICENSE_ID,
                )

        mutations = (
            lambda value: [],
            lambda value: {**value, "name": ""},
            lambda value: {**value, "documentNamespace": None},
            lambda value: {
                **value,
                "creationInfo": {**value["creationInfo"], "created": None},
            },
            lambda value: {**value, "packages": []},
            lambda value: {
                **value,
                "packages": [
                    value["packages"][0],
                    {**value["packages"][1], "versionInfo": "9.9.9"},
                ],
            },
            lambda value: {
                **value,
                "packages": [
                    {**value["packages"][0], "SPDXID": "invalid"},
                    value["packages"][1],
                ],
            },
            lambda value: {
                **value,
                "relationships": [
                    "not-an-object",
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relatedSpdxElement": "SPDXRef-DOCUMENT",
                        "relationshipType": "CONTAINS",
                    },
                ],
            },
        )
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                document = mutate(copy.deepcopy(_spdx_document()))
                _write_asset_set(root, document)
                with self.assertRaises(ReleaseEvidenceError):
                    validate_spdx_sbom(
                        root / SBOM_NAME,
                        project_name=PROJECT_NAME,
                        version=VERSION,
                        license_id=LICENSE_ID,
                    )


if __name__ == "__main__":
    unittest.main()
