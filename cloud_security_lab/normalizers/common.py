"""Shared helpers for native cloud evidence normalizers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_normalized_environment(path: Path, environment: dict[str, Any]) -> None:
    """Write normalized analyzer input in deterministic, human-readable JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(environment, handle, indent=2, sort_keys=True)
        handle.write("\n")
