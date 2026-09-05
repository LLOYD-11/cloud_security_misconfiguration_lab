from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from tools.evaluation_replay import EvaluationReplayError, main, replay_evaluation

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class EvaluationReplayTests(unittest.TestCase):
    def test_replay_requires_full_git_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(EvaluationReplayError, "full Git history"):
                replay_evaluation(Path(directory))

    def test_cli_reports_invalid_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(("--root", directory))

        self.assertEqual(1, result)
        self.assertIn("Evaluation replay failed", output.getvalue())


if __name__ == "__main__":
    unittest.main()
