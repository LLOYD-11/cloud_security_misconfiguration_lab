import copy
import json
import tempfile
import unittest
from pathlib import Path

from cloud_rules import (
    load_builtin_catalog,
    load_rule_catalog_file,
    render_rule_catalog_markdown,
    rule_catalog_from_dict,
    rule_catalog_to_dict,
    validate_rule_emission,
)


class RuleCatalogTests(unittest.TestCase):
    def setUp(self):
        self.catalog = load_builtin_catalog()
        self.payload = rule_catalog_to_dict(self.catalog)

    def test_builtin_catalog_has_expected_module_counts(self):
        counts = {
            module: len([rule for rule in self.catalog.rules if rule.module == module])
            for module in ("iam", "storage", "network", "cloudtrail")
        }

        self.assertEqual(
            {"iam": 15, "storage": 6, "network": 3, "cloudtrail": 11},
            counts,
        )
        self.assertEqual(35, len(self.catalog.rules))

    def test_catalog_round_trip_and_file_loader(self):
        self.assertEqual(self.catalog, rule_catalog_from_dict(self.payload))
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "catalog.json"
            path.write_text(json.dumps(self.payload), encoding="utf-8")
            loaded = load_rule_catalog_file(path)

        self.assertEqual(self.catalog, loaded)

    def test_filtered_catalog_updates_count_on_serialization(self):
        filtered = self.catalog.filtered("network")
        payload = rule_catalog_to_dict(filtered)

        self.assertEqual(3, payload["rule_count"])
        self.assertEqual(
            {"NET-001", "NET-002", "NET-003"},
            {rule["rule_id"] for rule in payload["rules"]},
        )

    def test_unknown_catalog_filter_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Catalog module"):
            self.catalog.filtered("database")

    def test_catalog_count_and_unknown_fields_are_strict(self):
        wrong_count = copy.deepcopy(self.payload)
        wrong_count["rule_count"] += 1
        with self.assertRaisesRegex(ValueError, "rule_count"):
            rule_catalog_from_dict(wrong_count)

        unknown_field = copy.deepcopy(self.payload)
        unknown_field["rules"][0]["notes"] = "unsupported"
        with self.assertRaisesRegex(ValueError, "unsupported fields: notes"):
            rule_catalog_from_dict(unknown_field)

    def test_catalog_top_level_types_and_required_fields_are_strict(self):
        with self.assertRaisesRegex(ValueError, "must be a JSON object"):
            rule_catalog_from_dict([])

        missing = copy.deepcopy(self.payload)
        del missing["rules"]
        with self.assertRaisesRegex(ValueError, "missing fields: rules"):
            rule_catalog_from_dict(missing)

        cases = (
            ("frameworks", {}, "frameworks must be a JSON list"),
            ("rules", {}, "rules must be a JSON list"),
            ("rule_count", True, "rule_count must be an integer"),
        )
        for field_name, value, message in cases:
            with self.subTest(field=field_name):
                invalid = copy.deepcopy(self.payload)
                invalid[field_name] = value
                with self.assertRaisesRegex(ValueError, message):
                    rule_catalog_from_dict(invalid)

    def test_rule_identity_and_text_contracts_are_strict(self):
        cases = (
            ("rule_id", "IAM-1", "rule_id must match"),
            ("module", "database", "module must be one of"),
            ("title", "", "title must be a non-empty string"),
            ("default_severity", "urgent", "invalid default_severity"),
            ("confidence", "certain", "confidence must be one of"),
        )
        for field_name, value, message in cases:
            with self.subTest(field=field_name):
                invalid = copy.deepcopy(self.payload)
                invalid["rules"][0][field_name] = value
                with self.assertRaisesRegex(ValueError, message):
                    rule_catalog_from_dict(invalid)

        wrong_prefix = copy.deepcopy(self.payload)
        wrong_prefix["rules"][0]["module"] = "storage"
        with self.assertRaisesRegex(ValueError, "does not match module"):
            rule_catalog_from_dict(wrong_prefix)

    def test_rule_severity_and_mapping_contracts_are_strict(self):
        invalid_default = copy.deepcopy(self.payload)
        invalid_default["rules"][0]["default_severity"] = "high"
        with self.assertRaisesRegex(ValueError, "default_severity must be allowed"):
            rule_catalog_from_dict(invalid_default)

        invalid_relationship = copy.deepcopy(self.payload)
        invalid_relationship["rules"][0]["mappings"][0]["relationship"] = "covers"
        with self.assertRaisesRegex(ValueError, "relationship"):
            rule_catalog_from_dict(invalid_relationship)

        invalid_url = copy.deepcopy(self.payload)
        invalid_url["rules"][0]["mappings"][0]["url"] = "http://example.com"
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            rule_catalog_from_dict(invalid_url)

        invalid_allowed_type = copy.deepcopy(self.payload)
        invalid_allowed_type["rules"][0]["allowed_severities"] = "critical"
        with self.assertRaisesRegex(ValueError, "must be a JSON list"):
            rule_catalog_from_dict(invalid_allowed_type)

        invalid_allowed_value = copy.deepcopy(self.payload)
        invalid_allowed_value["rules"][0]["allowed_severities"] = ["urgent"]
        with self.assertRaisesRegex(ValueError, "must contain valid severities"):
            rule_catalog_from_dict(invalid_allowed_value)

        duplicate_allowed = copy.deepcopy(self.payload)
        duplicate_allowed["rules"][0]["allowed_severities"] = [
            "critical",
            "critical",
        ]
        with self.assertRaisesRegex(ValueError, "must not contain duplicates"):
            rule_catalog_from_dict(duplicate_allowed)

        invalid_mapping_type = copy.deepcopy(self.payload)
        invalid_mapping_type["rules"][0]["mappings"] = {}
        with self.assertRaisesRegex(ValueError, "mappings must be a JSON list"):
            rule_catalog_from_dict(invalid_mapping_type)

        empty_mappings = copy.deepcopy(self.payload)
        empty_mappings["rules"][0]["mappings"] = []
        with self.assertRaisesRegex(ValueError, "must have at least one mapping"):
            rule_catalog_from_dict(empty_mappings)

        duplicate_mappings = copy.deepcopy(self.payload)
        duplicate_mappings["rules"][5]["mappings"].append(
            copy.deepcopy(duplicate_mappings["rules"][5]["mappings"][0])
        )
        with self.assertRaisesRegex(ValueError, "must not contain duplicates"):
            rule_catalog_from_dict(duplicate_mappings)

        unsorted_mappings = copy.deepcopy(self.payload)
        unsorted_mappings["rules"][5]["mappings"].reverse()
        with self.assertRaisesRegex(ValueError, "deterministic order"):
            rule_catalog_from_dict(unsorted_mappings)

    def test_unknown_framework_and_duplicate_rules_are_rejected(self):
        unknown_framework = copy.deepcopy(self.payload)
        unknown_framework["rules"][0]["mappings"][0]["framework"] = "unknown"
        with self.assertRaisesRegex(ValueError, "unknown framework"):
            rule_catalog_from_dict(unknown_framework)

        duplicate_rule = copy.deepcopy(self.payload)
        duplicate_rule["rules"][1] = copy.deepcopy(duplicate_rule["rules"][0])
        with self.assertRaisesRegex(ValueError, "rule IDs must be unique"):
            rule_catalog_from_dict(duplicate_rule)

    def test_catalog_identity_and_order_contracts_are_strict(self):
        wrong_version = copy.deepcopy(self.payload)
        wrong_version["schema_version"] = "2.0"
        with self.assertRaisesRegex(ValueError, "Unsupported rule catalog"):
            rule_catalog_from_dict(wrong_version)

        empty_frameworks = copy.deepcopy(self.payload)
        empty_frameworks["frameworks"] = []
        with self.assertRaisesRegex(ValueError, "frameworks must not be empty"):
            rule_catalog_from_dict(empty_frameworks)

        duplicate_frameworks = copy.deepcopy(self.payload)
        duplicate_frameworks["frameworks"][1] = copy.deepcopy(
            duplicate_frameworks["frameworks"][0]
        )
        with self.assertRaisesRegex(ValueError, "framework IDs must be unique"):
            rule_catalog_from_dict(duplicate_frameworks)

        unsorted_frameworks = copy.deepcopy(self.payload)
        unsorted_frameworks["frameworks"].reverse()
        with self.assertRaisesRegex(ValueError, "sorted by framework ID"):
            rule_catalog_from_dict(unsorted_frameworks)

        empty_rules = copy.deepcopy(self.payload)
        empty_rules["rule_count"] = 0
        empty_rules["rules"] = []
        with self.assertRaisesRegex(ValueError, "rules must not be empty"):
            rule_catalog_from_dict(empty_rules)

        unsorted_rules = copy.deepcopy(self.payload)
        unsorted_rules["rules"][0], unsorted_rules["rules"][1] = (
            unsorted_rules["rules"][1],
            unsorted_rules["rules"][0],
        )
        with self.assertRaisesRegex(ValueError, "module and rule ID order"):
            rule_catalog_from_dict(unsorted_rules)

    def test_rule_emission_validation_supports_explicit_custom_rules(self):
        rule = validate_rule_emission("IAM-001", "iam", "critical")
        self.assertIsNotNone(rule)

        with self.assertRaisesRegex(ValueError, "belongs to module iam"):
            validate_rule_emission("IAM-001", "storage", "critical")
        with self.assertRaisesRegex(ValueError, "severity 'high' is not allowed"):
            validate_rule_emission("IAM-001", "iam", "high")
        with self.assertRaisesRegex(ValueError, "not present"):
            validate_rule_emission("CUSTOM-001", "custom", "medium")
        self.assertIsNone(
            validate_rule_emission(
                "CUSTOM-001",
                "custom",
                "medium",
                require_known=False,
            )
        )

    def test_markdown_explains_mapping_and_confidence_semantics(self):
        markdown = render_rule_catalog_markdown(self.catalog.filtered("storage"))

        self.assertIn("# Detection Rule Catalog", markdown)
        self.assertIn("Confidence describes", markdown)
        self.assertIn("`direct` means", markdown)
        self.assertIn("## Storage", markdown)
        self.assertIn("### STO-003", markdown)
        self.assertNotIn("### IAM-001", markdown)
        self.assertLess(markdown.index("| `STO-006` |"), markdown.index("### STO-001"))


if __name__ == "__main__":
    unittest.main()
