import ast
import unittest
from pathlib import Path
from urllib.parse import urlparse

from cloud_rules import load_builtin_catalog
from cloudtrail_detector.detector import (
    analyze_environment as analyze_cloudtrail,
    load_environment as load_cloudtrail,
)
from iam_analyzer.analyzer import analyze_environment as analyze_iam, load_environment as load_iam
from network_analyzer.analyzer import (
    analyze_environment as analyze_network,
    load_environment as load_network,
)
from storage_analyzer.analyzer import (
    analyze_environment as analyze_storage,
    load_environment as load_storage,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ANALYZER_SOURCES = {
    "iam": PROJECT_ROOT / "iam_analyzer/analyzer.py",
    "storage": PROJECT_ROOT / "storage_analyzer/analyzer.py",
    "network": PROJECT_ROOT / "network_analyzer/analyzer.py",
    "cloudtrail": PROJECT_ROOT / "cloudtrail_detector/detector.py",
}


def _literal_rule_ids(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    rule_ids = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "_add_finding":
            continue
        for keyword in node.keywords:
            if keyword.arg == "rule_id" and isinstance(keyword.value, ast.Constant):
                if isinstance(keyword.value.value, str):
                    rule_ids.add(keyword.value.value)
    return rule_ids


class RuleCatalogCompletenessTests(unittest.TestCase):
    def test_catalog_exactly_matches_rule_ids_declared_by_analyzers(self):
        catalog = load_builtin_catalog()

        for module, source_path in ANALYZER_SOURCES.items():
            with self.subTest(module=module):
                catalog_ids = {
                    rule.rule_id for rule in catalog.rules if rule.module == module
                }
                self.assertEqual(_literal_rule_ids(source_path), catalog_ids)

    def test_all_catalog_rules_have_qualified_authoritative_mappings(self):
        catalog = load_builtin_catalog()
        allowed_hosts = {"attack.mitre.org", "docs.aws.amazon.com"}

        for rule in catalog.rules:
            with self.subTest(rule=rule.rule_id):
                self.assertTrue(rule.mappings)
                self.assertTrue(rule.confidence_basis)
                for mapping in rule.mappings:
                    self.assertIn(mapping.relationship, {"direct", "related"})
                    self.assertIn(urlparse(mapping.url).hostname, allowed_hosts)
                    self.assertTrue(mapping.rationale)

    def test_verified_cis_threshold_mappings_preserve_relationship_semantics(self):
        catalog = load_builtin_catalog()
        iam_007 = catalog.get("IAM-007")
        iam_011 = catalog.get("IAM-011")
        self.assertIsNotNone(iam_007)
        self.assertIsNotNone(iam_011)

        rotation = next(
            mapping
            for mapping in iam_007.mappings
            if mapping.framework == "cis-aws-foundations"
        )
        stale_credential = next(
            mapping
            for mapping in iam_011.mappings
            if mapping.framework == "cis-aws-foundations"
        )
        self.assertEqual("1.13", rotation.control_id)
        self.assertEqual("direct", rotation.relationship)
        self.assertIn("90 days", rotation.title)
        self.assertEqual("1.11", stale_credential.control_id)
        self.assertEqual("related", stale_credential.relationship)
        self.assertIn("45 days", stale_credential.title)

    def test_current_mitre_parent_and_cloud_log_subtechnique_are_distinct(self):
        rule = load_builtin_catalog().get("CLD-010")
        self.assertIsNotNone(rule)
        mappings = {mapping.control_id: mapping for mapping in rule.mappings}

        self.assertEqual("Disable or Modify Tools", mappings["T1685"].title)
        self.assertEqual("direct", mappings["T1685"].relationship)
        self.assertIn("Cloud Log", mappings["T1685.002"].title)
        self.assertEqual("related", mappings["T1685.002"].relationship)

    def test_all_bundled_sample_findings_resolve_to_catalog_rules(self):
        catalog = load_builtin_catalog()
        known_rule_ids = {rule.rule_id for rule in catalog.rules}
        analyzers = (
            (
                analyze_iam,
                load_iam(PROJECT_ROOT / "sample_data/iam/sample_iam_environment.json"),
            ),
            (
                analyze_storage,
                load_storage(
                    PROJECT_ROOT
                    / "sample_data/storage/sample_storage_environment.json"
                ),
            ),
            (
                analyze_network,
                load_network(
                    PROJECT_ROOT
                    / "sample_data/network/sample_network_environment.json"
                ),
            ),
            (
                analyze_cloudtrail,
                load_cloudtrail(
                    PROJECT_ROOT
                    / "sample_data/cloudtrail/sample_cloudtrail_events.json"
                ),
            ),
        )

        findings = [
            finding
            for analyzer, environment in analyzers
            for finding in analyzer(environment)
        ]
        self.assertEqual(39, len(findings))
        self.assertTrue(findings)
        self.assertTrue(
            all(finding.rule_id in known_rule_ids for finding in findings)
        )


if __name__ == "__main__":
    unittest.main()
