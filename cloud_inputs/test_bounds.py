import gzip
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from cloud_inputs import (
    DEFAULT_INPUT_LIMITS,
    InputLimitError,
    InputLimits,
    JsonBudget,
    enforce_collection_limit,
    enforce_input_file_count,
    enforce_primary_resource_limit,
    load_bounded_json,
    parse_bounded_json_text,
    primary_resource_count,
    validate_analysis_input_limits,
    validate_json_value_limits,
)


class InputBoundsTests(unittest.TestCase):
    def test_default_limits_preserve_measured_scale_headroom(self):
        self.assertEqual(32 * 1024 * 1024, DEFAULT_INPUT_LIMITS.max_json_file_bytes)
        self.assertEqual(
            64 * 1024 * 1024,
            DEFAULT_INPUT_LIMITS.max_gzip_decompressed_bytes,
        )
        self.assertEqual(1_000_000, DEFAULT_INPUT_LIMITS.max_json_nodes)
        self.assertEqual(64, DEFAULT_INPUT_LIMITS.max_json_depth)
        self.assertEqual(10_000, DEFAULT_INPUT_LIMITS.max_primary_resources)
        self.assertEqual(100, DEFAULT_INPUT_LIMITS.max_input_files)

    def test_limits_must_be_positive_integers(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value), self.assertRaisesRegex(
                ValueError,
                "must be a positive integer",
            ):
                InputLimits(max_json_nodes=value)  # type: ignore[arg-type]

    def test_raw_json_file_size_is_enforced_at_the_exact_boundary(self):
        content = b'{"a":1}'
        limits = replace(
            DEFAULT_INPUT_LIMITS,
            max_json_file_bytes=len(content),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "input.json"
            path.write_bytes(content)
            self.assertEqual(
                {"a": 1},
                load_bounded_json(path, label="Test JSON", limits=limits),
            )

            path.write_bytes(content + b" ")
            with self.assertRaisesRegex(
                InputLimitError,
                r"Test JSON exceeds the file-size limit of 7 bytes",
            ):
                load_bounded_json(path, label="Test JSON", limits=limits)

    def test_depth_scan_ignores_container_characters_inside_strings(self):
        limits = replace(DEFAULT_INPUT_LIMITS, max_json_depth=2)
        accepted = '{"text":"[[[{\\"nested\\":true}", "items":[1]}'
        self.assertEqual(
            {"text": '[[[{"nested":true}', "items": [1]},
            parse_bounded_json_text(
                accepted,
                label="Test JSON",
                limits=limits,
            ),
        )

        with self.assertRaisesRegex(
            InputLimitError,
            r"nesting-depth limit of 2",
        ):
            parse_bounded_json_text(
                '{"items":[[1]]}',
                label="Test JSON",
                limits=limits,
            )

    def test_node_limit_counts_containers_and_scalar_values(self):
        payload = '{"items":[1,2]}'
        accepted_limits = replace(DEFAULT_INPUT_LIMITS, max_json_nodes=4)
        metrics = validate_json_value_limits(
            parse_bounded_json_text(
                payload,
                label="Test JSON",
                limits=accepted_limits,
            ),
            label="Test JSON",
            limits=accepted_limits,
        )
        self.assertEqual(4, metrics.node_count)
        self.assertEqual(2, metrics.max_depth)

        rejected_limits = replace(DEFAULT_INPUT_LIMITS, max_json_nodes=3)
        with self.assertRaisesRegex(
            InputLimitError,
            r"node-count limit of 3",
        ):
            parse_bounded_json_text(
                payload,
                label="Test JSON",
                limits=rejected_limits,
            )

    def test_gzip_compressed_and_decompressed_limits_are_independent(self):
        content = b'{"Records":[{"eventID":"example"}]}'
        compressed = gzip.compress(content)
        valid_limits = replace(
            DEFAULT_INPUT_LIMITS,
            max_gzip_file_bytes=len(compressed),
            max_gzip_decompressed_bytes=len(content),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "events.json.gz"
            path.write_bytes(compressed)
            self.assertEqual(
                {"Records": [{"eventID": "example"}]},
                load_bounded_json(
                    path,
                    label="CloudTrail test",
                    allow_gzip=True,
                    limits=valid_limits,
                ),
            )

            compressed_limits = replace(
                valid_limits,
                max_gzip_file_bytes=len(compressed) - 1,
            )
            with self.assertRaisesRegex(InputLimitError, "compressed-size limit"):
                load_bounded_json(
                    path,
                    label="CloudTrail test",
                    allow_gzip=True,
                    limits=compressed_limits,
                )

            decompressed_limits = replace(
                valid_limits,
                max_gzip_decompressed_bytes=len(content) - 1,
            )
            with self.assertRaisesRegex(InputLimitError, "decompressed-size limit"):
                load_bounded_json(
                    path,
                    label="CloudTrail test",
                    allow_gzip=True,
                    limits=decompressed_limits,
                )

    def test_truncated_gzip_fails_closed(self):
        compressed = gzip.compress(b'{"Records":[]}')
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "events.json.gz"
            path.write_bytes(compressed[:-4])
            with self.assertRaises((gzip.BadGzipFile, EOFError)):
                load_bounded_json(
                    path,
                    label="CloudTrail test",
                    allow_gzip=True,
                )

    def test_related_files_share_aggregate_byte_and_node_budgets(self):
        byte_limits = replace(
            DEFAULT_INPUT_LIMITS,
            max_total_decoded_bytes=13,
        )
        byte_budget = JsonBudget("Test input set", limits=byte_limits)
        parse_bounded_json_text(
            '{"a":1}',
            label="First",
            limits=byte_limits,
            budget=byte_budget,
        )
        with self.assertRaisesRegex(
            InputLimitError,
            "aggregate decoded-size limit",
        ):
            parse_bounded_json_text(
                '{"b":2}',
                label="Second",
                limits=byte_limits,
                budget=byte_budget,
            )

        node_limits = replace(
            DEFAULT_INPUT_LIMITS,
            max_json_nodes=3,
        )
        node_budget = JsonBudget("Test input set", limits=node_limits)
        parse_bounded_json_text(
            '{"a":1}',
            label="First",
            limits=node_limits,
            budget=node_budget,
        )
        with self.assertRaisesRegex(
            InputLimitError,
            "aggregate JSON node-count limit",
        ):
            parse_bounded_json_text(
                "[0]",
                label="Second",
                limits=node_limits,
                budget=node_budget,
            )

    def test_file_collection_and_primary_resource_limits_are_enforced(self):
        limits = replace(
            DEFAULT_INPUT_LIMITS,
            max_input_files=2,
            max_primary_resources=2,
        )
        enforce_input_file_count(2, label="Test inputs", limits=limits)
        with self.assertRaisesRegex(InputLimitError, "contains 3 files"):
            enforce_input_file_count(3, label="Test inputs", limits=limits)

        enforce_collection_limit(2, label="Test artifacts", limits=limits)
        with self.assertRaisesRegex(InputLimitError, "contains 3 items"):
            enforce_collection_limit(3, label="Test artifacts", limits=limits)

        iam_environment = {
            "users": [{}],
            "groups": [],
            "roles": [],
            "root_account": {},
        }
        self.assertEqual(2, primary_resource_count("iam", iam_environment))
        enforce_primary_resource_limit(
            "iam",
            iam_environment,
            limits=limits,
        )
        iam_environment["roles"] = [{}]
        with self.assertRaisesRegex(
            InputLimitError,
            "contains 3 primary resources",
        ):
            enforce_primary_resource_limit(
                "iam",
                iam_environment,
                limits=limits,
            )

    def test_analysis_input_limits_cover_in_memory_callers(self):
        limits = replace(
            DEFAULT_INPUT_LIMITS,
            max_json_nodes=5,
            max_primary_resources=1,
        )
        validate_analysis_input_limits(
            "cloudtrail",
            {"account_id": "111122223333", "events": []},
            limits=limits,
        )
        with self.assertRaisesRegex(InputLimitError, "node-count limit"):
            validate_analysis_input_limits(
                "cloudtrail",
                {
                    "account_id": "111122223333",
                    "events": [{"id": "one", "detail": {"nested": True}}],
                },
                limits=limits,
            )

    def test_malformed_json_and_invalid_utf8_keep_parser_specific_errors(self):
        with self.assertRaises(json.JSONDecodeError):
            parse_bounded_json_text("{", label="Test JSON")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "input.json"
            path.write_bytes(b"\xff")
            with self.assertRaises(UnicodeDecodeError):
                load_bounded_json(path, label="Test JSON")


if __name__ == "__main__":
    unittest.main()
