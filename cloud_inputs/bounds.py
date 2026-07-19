"""Shared resource limits for untrusted offline input files."""

from __future__ import annotations

import gzip
import io
import json
import zlib
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Sequence

MEBIBYTE = 1024 * 1024


@dataclass(frozen=True)
class InputLimits:
    """Resource ceilings applied before untrusted evidence is analyzed."""

    max_json_file_bytes: int = 32 * MEBIBYTE
    max_gzip_file_bytes: int = 32 * MEBIBYTE
    max_gzip_decompressed_bytes: int = 64 * MEBIBYTE
    max_total_decoded_bytes: int = 64 * MEBIBYTE
    max_json_nodes: int = 1_000_000
    max_json_depth: int = 64
    max_primary_resources: int = 10_000
    max_input_files: int = 100

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"Input limit {field.name} must be a positive integer.")


DEFAULT_INPUT_LIMITS = InputLimits()


class InputLimitError(ValueError):
    """Raised when an input exceeds a documented resource ceiling."""


@dataclass(frozen=True)
class JsonMetrics:
    """Measured size of one decoded JSON value."""

    decoded_bytes: int
    node_count: int
    max_depth: int


@dataclass
class JsonBudget:
    """Aggregate decoded-byte and node budget across related input files."""

    label: str
    limits: InputLimits = DEFAULT_INPUT_LIMITS
    decoded_bytes: int = 0
    node_count: int = 0

    def consume(self, metrics: JsonMetrics) -> None:
        """Charge one parsed document to this aggregate budget."""

        decoded_bytes = self.decoded_bytes + metrics.decoded_bytes
        node_count = self.node_count + metrics.node_count
        if decoded_bytes > self.limits.max_total_decoded_bytes:
            raise InputLimitError(
                f"{self.label} exceeds the aggregate decoded-size limit of "
                f"{_format_bytes(self.limits.max_total_decoded_bytes)}."
            )
        if node_count > self.limits.max_json_nodes:
            raise InputLimitError(
                f"{self.label} exceeds the aggregate JSON node-count limit of "
                f"{self.limits.max_json_nodes:,}."
            )
        self.decoded_bytes = decoded_bytes
        self.node_count = node_count


RESOURCE_KEYS = {
    "iam": ("users", "groups", "roles"),
    "storage": ("buckets",),
    "network": ("security_groups",),
    "cloudtrail": ("events",),
}


def _format_bytes(value: int) -> str:
    if value % MEBIBYTE == 0:
        return f"{value // MEBIBYTE} MiB"
    return f"{value:,} bytes"


def _read_limited(path: Path, *, label: str, max_bytes: int, kind: str) -> bytes:
    with path.open("rb") as handle:
        content = handle.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise InputLimitError(
            f"{label} exceeds the {kind} limit of {_format_bytes(max_bytes)}."
        )
    return content


def read_bounded_utf8(
    path: Path,
    *,
    label: str,
    max_bytes: int = DEFAULT_INPUT_LIMITS.max_json_file_bytes,
) -> str:
    """Read one UTF-8 text file without crossing its byte ceiling."""

    content = _read_limited(
        path,
        label=label,
        max_bytes=max_bytes,
        kind="file-size",
    )
    return content.decode("utf-8")


def _read_bounded_gzip_utf8(
    path: Path,
    *,
    label: str,
    limits: InputLimits,
) -> tuple[str, int]:
    compressed = _read_limited(
        path,
        label=label,
        max_bytes=limits.max_gzip_file_bytes,
        kind="compressed-size",
    )
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as handle:
            content = handle.read(limits.max_gzip_decompressed_bytes + 1)
    except (gzip.BadGzipFile, EOFError, zlib.error) as exc:
        raise gzip.BadGzipFile(str(exc)) from exc
    if len(content) > limits.max_gzip_decompressed_bytes:
        raise InputLimitError(
            f"{label} exceeds the decompressed-size limit of "
            f"{_format_bytes(limits.max_gzip_decompressed_bytes)}."
        )
    return content.decode("utf-8"), len(content)


def _enforce_text_depth(
    text: str,
    *,
    label: str,
    limits: InputLimits,
) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue

        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > limits.max_json_depth:
                raise InputLimitError(
                    f"{label} exceeds the JSON nesting-depth limit of "
                    f"{limits.max_json_depth}."
                )
        elif character in "]}":
            depth = max(0, depth - 1)


def _measure_json_value(
    value: Any,
    *,
    label: str,
    limits: InputLimits,
    decoded_bytes: int,
) -> JsonMetrics:
    node_count = 0
    max_depth = 0
    initial_depth = 1 if isinstance(value, (dict, list)) else 0
    stack = [(value, initial_depth)]
    while stack:
        item, depth = stack.pop()
        node_count += 1
        if node_count > limits.max_json_nodes:
            raise InputLimitError(
                f"{label} exceeds the JSON node-count limit of "
                f"{limits.max_json_nodes:,}."
            )
        max_depth = max(max_depth, depth)
        if depth > limits.max_json_depth:
            raise InputLimitError(
                f"{label} exceeds the JSON nesting-depth limit of "
                f"{limits.max_json_depth}."
            )
        if isinstance(item, dict):
            stack.extend(
                (
                    child,
                    depth + 1 if isinstance(child, (dict, list)) else depth,
                )
                for child in item.values()
            )
        elif isinstance(item, list):
            stack.extend(
                (
                    child,
                    depth + 1 if isinstance(child, (dict, list)) else depth,
                )
                for child in item
            )
    return JsonMetrics(
        decoded_bytes=decoded_bytes,
        node_count=node_count,
        max_depth=max_depth,
    )


def _parse_bounded_json_text(
    text: str,
    *,
    label: str,
    limits: InputLimits,
    budget: JsonBudget | None = None,
    max_bytes: int,
    decoded_bytes: int,
) -> Any:
    if decoded_bytes > max_bytes:
        raise InputLimitError(
            f"{label} exceeds the decoded-size limit of {_format_bytes(max_bytes)}."
        )
    _enforce_text_depth(text, label=label, limits=limits)
    try:
        value = json.loads(text)
    except RecursionError as exc:
        raise InputLimitError(
            f"{label} exceeds the JSON nesting-depth limit of "
            f"{limits.max_json_depth}."
        ) from exc
    metrics = _measure_json_value(
        value,
        label=label,
        limits=limits,
        decoded_bytes=decoded_bytes,
    )
    if budget is not None:
        budget.consume(metrics)
    return value


def parse_bounded_json_text(
    text: str,
    *,
    label: str,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
    budget: JsonBudget | None = None,
) -> Any:
    """Parse JSON text after enforcing byte, depth, and node ceilings."""

    return _parse_bounded_json_text(
        text,
        label=label,
        limits=limits,
        budget=budget,
        max_bytes=limits.max_json_file_bytes,
        decoded_bytes=len(text.encode("utf-8")),
    )


def load_bounded_json(
    path: Path,
    *,
    label: str,
    allow_gzip: bool = False,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
    budget: JsonBudget | None = None,
) -> Any:
    """Load one bounded UTF-8 JSON document, optionally from gzip."""

    if allow_gzip and path.suffix.lower() == ".gz":
        text, decoded_bytes = _read_bounded_gzip_utf8(
            path,
            label=label,
            limits=limits,
        )
        return _parse_bounded_json_text(
            text,
            label=label,
            limits=limits,
            budget=budget,
            max_bytes=limits.max_gzip_decompressed_bytes,
            decoded_bytes=decoded_bytes,
        )

    content = _read_limited(
        path,
        label=label,
        max_bytes=limits.max_json_file_bytes,
        kind="file-size",
    )
    text = content.decode("utf-8")
    return _parse_bounded_json_text(
        text,
        label=label,
        limits=limits,
        budget=budget,
        max_bytes=limits.max_json_file_bytes,
        decoded_bytes=len(content),
    )


def validate_json_value_limits(
    value: Any,
    *,
    label: str,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
    budget: JsonBudget | None = None,
) -> JsonMetrics:
    """Apply node and depth limits to an already-decoded JSON-compatible value."""

    metrics = _measure_json_value(
        value,
        label=label,
        limits=limits,
        decoded_bytes=0,
    )
    if budget is not None:
        budget.consume(metrics)
    return metrics


def enforce_collection_limit(
    count: int,
    *,
    label: str,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
) -> None:
    """Reject a resource or artifact collection above the shared ceiling."""

    if count > limits.max_primary_resources:
        raise InputLimitError(
            f"{label} contains {count:,} items; "
            f"limit is {limits.max_primary_resources:,}."
        )


def enforce_input_file_count(
    paths_or_count: Sequence[object] | int,
    *,
    label: str,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
) -> None:
    """Reject an input set with too many separate files."""

    count = (
        paths_or_count
        if isinstance(paths_or_count, int)
        else len(paths_or_count)
    )
    if count > limits.max_input_files:
        raise InputLimitError(
            f"{label} contains {count:,} files; "
            f"limit is {limits.max_input_files:,}."
        )


def primary_resource_count(module: str, environment: dict[str, Any]) -> int:
    """Count the primary resources represented by one analyzer environment."""

    try:
        keys = RESOURCE_KEYS[module]
    except KeyError as exc:
        supported = ", ".join(sorted(RESOURCE_KEYS))
        raise ValueError(
            f"Unsupported resource-count module {module!r}; "
            f"expected one of: {supported}."
        ) from exc
    count = sum(
        len(value)
        for key in keys
        if isinstance((value := environment.get(key)), list)
    )
    if module == "iam" and isinstance(environment.get("root_account"), dict):
        count += 1
    return count


def enforce_primary_resource_limit(
    module: str,
    environment: dict[str, Any],
    *,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
) -> None:
    """Reject an analyzer environment above its primary-resource ceiling."""

    count = primary_resource_count(module, environment)
    if count > limits.max_primary_resources:
        raise InputLimitError(
            f"{module.upper()} environment contains {count:,} primary resources; "
            f"limit is {limits.max_primary_resources:,}."
        )


def validate_analysis_input_limits(
    module: str,
    environment: dict[str, Any],
    *,
    limits: InputLimits = DEFAULT_INPUT_LIMITS,
) -> None:
    """Apply in-memory structural and primary-resource ceilings."""

    validate_json_value_limits(
        environment,
        label=f"{module.upper()} environment",
        limits=limits,
    )
    enforce_primary_resource_limit(module, environment, limits=limits)
