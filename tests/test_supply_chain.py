import re
import unittest
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_PYTHON_FLOOR = "3.10"
WORKFLOWS = (
    PROJECT_ROOT / ".github/workflows/ci.yml",
    PROJECT_ROOT / ".github/workflows/release.yml",
)
EXPECTED_ACTION_COUNTS = Counter(
    {
        (
            "actions/checkout",
            "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
            "v7.0.0",
        ): 2,
        (
            "actions/setup-python",
            "ece7cb06caefa5fff74198d8649806c4678c61a1",
            "v6.3.0",
        ): 2,
        (
            "anchore/sbom-action",
            "e22c389904149dbc22b58101806040fa8d37a610",
            "v0.24.0",
        ): 1,
        (
            "actions/attest",
            "f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
            "v4.2.0",
        ): 2,
        (
            "actions/upload-artifact",
            "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "v7.0.1",
        ): 1,
        (
            "actions/download-artifact",
            "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            "v8.0.1",
        ): 1,
    }
)
ACTION_PATTERN = re.compile(
    r"^\s*uses:\s*([^@\s]+)@([0-9a-f]{40})\s+#\s+(\S+)\s*$",
    re.MULTILINE,
)
REQUIREMENT_PATTERN = re.compile(
    r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)(?:\s*;[^\\]+)?\s*\\?$"
)
HASH_PATTERN = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s*\\)?$")


def _normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _declared_dev_dependencies() -> set[str]:
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    section = pyproject.split("[project.optional-dependencies]", 1)[1].split(
        "\n[",
        1,
    )[0]
    match = re.search(r"(?ms)^dev = \[\n(.*?)^\]\n", section)
    if match is None:
        raise AssertionError("pyproject.toml must declare a dev optional dependency list.")
    specifications = re.findall(r'^\s*"([^"]+)",\s*$', match.group(1), re.MULTILINE)
    names = {
        _normalized_name(re.match(r"^[A-Za-z0-9_.-]+", value).group())
        for value in specifications
    }
    return names


def _locked_requirements() -> dict[str, tuple[str, ...]]:
    lines = (PROJECT_ROOT / "requirements-dev.lock").read_text(
        encoding="utf-8"
    ).splitlines()
    packages: dict[str, list[str]] = {}
    current_name: str | None = None
    for line in lines:
        if line and not line[0].isspace() and not line.startswith("#"):
            match = REQUIREMENT_PATTERN.fullmatch(line)
            if match is None:
                raise AssertionError(f"Unpinned lock requirement: {line}")
            current_name = _normalized_name(match.group(1))
            packages.setdefault(current_name, [])
            continue
        hash_match = HASH_PATTERN.search(line.strip())
        if hash_match is not None:
            if current_name is None:
                raise AssertionError("Lock hash appears before its requirement.")
            packages[current_name].append(hash_match.group(1))
    return {name: tuple(hashes) for name, hashes in packages.items()}


class SupplyChainTests(unittest.TestCase):
    def test_ci_matrix_covers_every_declared_python_minor(self):
        pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        workflow = (PROJECT_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        declared = set(
            re.findall(
                r'"Programming Language :: Python :: (3\.\d+)"',
                pyproject,
            )
        )
        matrix_match = re.search(r"python-version:\s*\[([^\]]+)\]", workflow)
        if matrix_match is None:
            raise AssertionError("CI must declare an inline Python version matrix.")
        exercised = set(re.findall(r'"(3\.\d+)"', matrix_match.group(1)))

        self.assertEqual({"3.10", "3.11", "3.12", "3.13"}, declared)
        self.assertEqual(declared, exercised)

    def test_lock_resolution_starts_at_supported_python_floor(self):
        pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        lock_header = "\n".join(
            (PROJECT_ROOT / "requirements-dev.lock")
            .read_text(encoding="utf-8")
            .splitlines()[:3]
        )

        self.assertIn(
            f'requires-python = ">={SUPPORTED_PYTHON_FLOOR}"',
            pyproject,
        )
        self.assertIn(
            f"--universal --python-version {SUPPORTED_PYTHON_FLOOR}",
            lock_header,
        )

    def test_workflow_actions_use_reviewed_immutable_commits(self):
        observed: list[tuple[str, str, str]] = []
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            uses_lines = re.findall(r"^\s*uses:\s*(\S.*)$", text, re.MULTILINE)
            matches = ACTION_PATTERN.findall(text)
            self.assertEqual(len(uses_lines), len(matches), path)
            observed.extend(matches)

        self.assertEqual(
            EXPECTED_ACTION_COUNTS,
            Counter(observed),
        )

    def test_workflows_enforce_the_locked_environment(self):
        required_fragments = (
            "runs-on: ubuntu-24.04",
            "cache-dependency-path: requirements-dev.lock",
            "python -m pip install --require-hashes -r requirements-dev.lock",
            "python -m pip install --no-build-isolation --no-deps -e .",
            "python -m pip check",
            "python -m build --no-isolation",
            "pymarkdown --strict-config scan --respect-gitignore .",
            "python -m tools.check_markdown_links internal",
            "python -m tools.check_markdown_links external",
        )
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            for fragment in required_fragments:
                with self.subTest(workflow=path.name, fragment=fragment):
                    self.assertIn(fragment, text)
            self.assertEqual(
                text.count("persist-credentials: false"),
                1,
                path,
            )

    def test_release_workflow_separates_build_and_publish_permissions(self):
        release = (PROJECT_ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )

        self.assertNotRegex(release, r"(?m)^permissions:")
        self.assertEqual(1, release.count("contents: read"))
        self.assertEqual(1, release.count("contents: write"))
        self.assertEqual(1, release.count("id-token: write"))
        self.assertEqual(1, release.count("attestations: write"))
        self.assertEqual(1, release.count("attestations: read"))
        self.assertNotIn("artifact-metadata:", release)
        publish = release.split("\n  publish:\n", 1)[1]
        self.assertNotIn("actions/checkout", publish)
        self.assertNotIn("python ", publish)

    def test_release_workflow_builds_and_reverifies_integrity_evidence(self):
        release = (PROJECT_ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        required_fragments = (
            "--target build/sbom-root dist/*.whl",
            "path: build/sbom-root",
            "format: spdx-json",
            "syft-version: v1.48.0",
            "SYFT_SOURCE_NAME: cloud-security-misconfiguration-lab-wheel",
            "SYFT_SOURCE_VERSION: ${{ env.RELEASE_VERSION }}",
            "upload-artifact: false",
            "upload-release-assets: false",
            "python -m tools.release_evidence prepare",
            "python -m tools.release_evidence verify",
            "dist/cloud-security-misconfiguration-lab.spdx.json",
            "dist/SHA256SUMS",
            "sbom-path: dist/cloud-security-misconfiguration-lab.spdx.json",
            "https://spdx.dev/Document/v2.3",
            "cloud-security-misconfiguration-lab-build-provenance.sigstore.json",
            "cloud-security-misconfiguration-lab-sbom-attestation.sigstore.json",
            "--signer-workflow",
            "sha256sum --check SHA256SUMS",
            "if-no-files-found: error",
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, release)
        self.assertEqual(2, release.count("gh attestation verify dist/*.whl"))
        self.assertEqual(2, release.count("for artifact in dist/*.whl"))

    def test_lock_covers_declared_tools_and_hashes_every_package(self):
        declared = _declared_dev_dependencies()
        locked = _locked_requirements()

        self.assertTrue(declared)
        self.assertTrue(declared.issubset(locked))
        self.assertTrue(locked)
        self.assertTrue(all(hashes for hashes in locked.values()))


if __name__ == "__main__":
    unittest.main()
