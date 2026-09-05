"""Replay the frozen M12 evaluation in an isolated candidate checkout."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_REVISION = "6d71c99914a38b6e161bc9cf56407eb1757b8c9a"
FROZEN_EVALUATION_PATHS = (
    Path("evaluation/baseline-outcomes-v1.0.json"),
    Path("evaluation/baseline-overlap-v1.0.json"),
    Path("evaluation/corpus-manifest-v1.0.json"),
    Path("evaluation/protocol-v1.0.json"),
    Path("evaluation/results-v1.0.json"),
)
FROZEN_CORPUS_PATH = Path("evaluation/corpus-v1.0")
FROZEN_TOOL_PATHS = (
    Path("tools/evaluation_baselines.py"),
    Path("tools/evaluation_corpus.py"),
    Path("tools/evaluation_runner.py"),
)
FROZEN_SCHEMA_PATHS = (
    Path("schemas/evaluation-baseline-outcomes-v1.0.schema.json"),
    Path("schemas/evaluation-baseline-overlap-v1.0.schema.json"),
    Path("schemas/evaluation-corpus-manifest-v1.0.schema.json"),
    Path("schemas/evaluation-protocol-v1.0.schema.json"),
    Path("schemas/evaluation-results-v1.0.schema.json"),
)


class EvaluationReplayError(ValueError):
    """Raised when the frozen candidate cannot be staged or replayed."""


def _run(command: Sequence[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise EvaluationReplayError(f"Unable to execute {command[0]}: {error}") from error


def _require_regular_file(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise EvaluationReplayError(f"{label} does not exist: {path}.") from error
    if path.is_symlink() or not resolved.is_file():
        raise EvaluationReplayError(f"{label} must be a regular file: {path}.")
    return resolved


def _copy_file(source_root: Path, destination_root: Path, relative_path: Path) -> None:
    source = _require_regular_file(source_root / relative_path, label="Frozen artifact")
    destination = destination_root / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _copy_tree(source_root: Path, destination_root: Path, relative_root: Path) -> None:
    source = source_root / relative_root
    if source.is_symlink() or not source.is_dir():
        raise EvaluationReplayError(f"Frozen artifact tree must be a directory: {source}.")
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise EvaluationReplayError(f"Frozen artifact tree cannot contain symlinks: {path}.")
        relative_path = path.relative_to(source_root)
        if path.is_dir():
            (destination_root / relative_path).mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            _copy_file(source_root, destination_root, relative_path)
        else:
            raise EvaluationReplayError(f"Unsupported frozen artifact entry: {path}.")


def _stage_candidate_checkout(source_root: Path, destination_root: Path) -> None:
    clone = _run(
        (
            "git",
            "clone",
            "--quiet",
            "--no-hardlinks",
            "--no-checkout",
            str(source_root),
            str(destination_root),
        ),
        cwd=source_root,
    )
    if clone.returncode != 0:
        detail = (clone.stderr or clone.stdout).strip()
        raise EvaluationReplayError(f"Unable to clone the local repository: {detail}")

    checkout = _run(
        ("git", "checkout", "--quiet", "--detach", CANDIDATE_REVISION),
        cwd=destination_root,
    )
    if checkout.returncode != 0:
        detail = (checkout.stderr or checkout.stdout).strip()
        raise EvaluationReplayError(
            f"Unable to check out frozen candidate {CANDIDATE_REVISION}: {detail}"
        )

    _copy_tree(source_root, destination_root, FROZEN_CORPUS_PATH)
    for path in (
        *FROZEN_EVALUATION_PATHS,
        *FROZEN_TOOL_PATHS,
        *FROZEN_SCHEMA_PATHS,
    ):
        _copy_file(source_root, destination_root, path)


def replay_evaluation(root: Path = PROJECT_ROOT) -> str:
    """Replay and verify the published result against the frozen candidate."""

    source_root = root.resolve(strict=True)
    if not (source_root / ".git").exists():
        raise EvaluationReplayError(
            f"Evaluation replay requires a repository with full Git history: {source_root}."
        )
    with tempfile.TemporaryDirectory(prefix="cloud-security-evaluation-") as directory:
        candidate_root = Path(directory) / "candidate"
        _stage_candidate_checkout(source_root, candidate_root)
        replay = _run(
            (
                sys.executable,
                "-m",
                "tools.evaluation_runner",
                "--root",
                str(candidate_root),
            ),
            cwd=candidate_root,
        )
        if replay.returncode != 0:
            detail = (replay.stdout + replay.stderr).strip()
            raise EvaluationReplayError(f"Frozen candidate replay failed: {detail}")
        return replay.stdout.strip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replay the immutable M12 result in a temporary checkout of the frozen "
            "candidate revision."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=PROJECT_ROOT,
        help="Repository root with full Git history and frozen evaluation artifacts.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        print(replay_evaluation(args.root))
    except (OSError, EvaluationReplayError) as error:
        print(f"Evaluation replay failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
