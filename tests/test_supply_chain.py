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
EXPECTED_ACTIONS = {
    (
        "actions/checkout",
        "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "v7.0.0",
    ),
    (
        "actions/setup-python",
        "ece7cb06caefa5fff74198d8649806c4678c61a1",
        "v6.3.0",
    ),
}
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
            Counter({action: len(WORKFLOWS) for action in EXPECTED_ACTIONS}),
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

    def test_lock_covers_declared_tools_and_hashes_every_package(self):
        declared = _declared_dev_dependencies()
        locked = _locked_requirements()

        self.assertTrue(declared)
        self.assertTrue(declared.issubset(locked))
        self.assertTrue(locked)
        self.assertTrue(all(hashes for hashes in locked.values()))


if __name__ == "__main__":
    unittest.main()
