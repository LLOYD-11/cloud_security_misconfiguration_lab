from __future__ import annotations

import ast
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.evaluation_corpus import (
    CorpusSummary,
    EvaluationCorpusError,
    verify_corpus,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = Path("evaluation/corpus-manifest-v1.0.json")


class EvaluationCorpusTests(unittest.TestCase):
    def _copy_verification_root(self) -> Path:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        root = Path(temporary_directory.name)
        shutil.copytree(PROJECT_ROOT / "evaluation", root / "evaluation")
        shutil.copytree(PROJECT_ROOT / "schemas", root / "schemas")
        (root / "cloud_rules").mkdir()
        shutil.copy2(
            PROJECT_ROOT / "cloud_rules/rules-v1.0.json",
            root / "cloud_rules/rules-v1.0.json",
        )
        return root

    def _load_manifest(self, root: Path) -> dict[str, Any]:
        return json.loads((root / MANIFEST_PATH).read_text(encoding="utf-8"))

    def _write_manifest(self, root: Path, manifest: dict[str, Any]) -> None:
        (root / MANIFEST_PATH).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _case(self, manifest: dict[str, Any], case_id: str) -> dict[str, Any]:
        return next(case for case in manifest["cases"] if case["id"] == case_id)

    def test_frozen_corpus_matches_registered_inventory(self):
        self.assertEqual(
            verify_corpus(PROJECT_ROOT),
            CorpusSummary(
                case_count=32,
                file_count=42,
                assertion_count=176,
                positive_assertions=78,
                negative_assertions=90,
                ambiguous_assertions=8,
                native_simplified_pairs=8,
            ),
        )

    def test_verifier_does_not_import_candidate_code(self):
        source_path = PROJECT_ROOT / "tools/evaluation_corpus.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_modules.add(node.module)

        candidate_roots = {
            "cloud_security_lab",
            "cloudtrail_detector",
            "iam_analyzer",
            "network_analyzer",
            "storage_analyzer",
        }
        self.assertFalse(
            any(module.split(".", 1)[0] in candidate_roots for module in imported_modules)
        )

    def test_evidence_digest_tampering_is_rejected(self):
        root = self._copy_verification_root()
        manifest = self._load_manifest(root)
        evidence_path = root / manifest["cases"][0]["input_variants"][0]["files"][0][
            "path"
        ]
        with evidence_path.open("ab") as handle:
            handle.write(b"\n")

        with self.assertRaisesRegex(EvaluationCorpusError, "size mismatch"):
            verify_corpus(root)

    def test_undeclared_corpus_file_is_rejected(self):
        root = self._copy_verification_root()
        extra_path = root / "evaluation/corpus-v1.0/iam/undeclared.json"
        extra_path.write_text("{}\n", encoding="utf-8")

        with self.assertRaisesRegex(EvaluationCorpusError, "inventory mismatch"):
            verify_corpus(root)

    def test_duplicate_decision_key_is_rejected(self):
        root = self._copy_verification_root()
        manifest = self._load_manifest(root)
        case = self._case(manifest, "EVAL-IAM-001")
        duplicate = dict(case["assertions"][0])
        duplicate["id"] = "AST-IAM-001-99"
        case["assertions"].append(duplicate)
        self._write_manifest(root, manifest)

        with self.assertRaisesRegex(EvaluationCorpusError, "Duplicate decision key"):
            verify_corpus(root)

    def test_rule_coverage_below_registered_minimum_is_rejected(self):
        root = self._copy_verification_root()
        manifest = self._load_manifest(root)
        removed = False
        for case in manifest["cases"]:
            for assertion in list(case["assertions"]):
                if assertion["rule_id"] == "IAM-005" and assertion["label"] == "negative":
                    case["assertions"].remove(assertion)
                    removed = True
                    break
            if removed:
                break
        self.assertTrue(removed)
        self._write_manifest(root, manifest)

        with self.assertRaisesRegex(EvaluationCorpusError, "IAM-005.*negative"):
            verify_corpus(root)

    def test_broken_native_simplified_pair_is_rejected(self):
        root = self._copy_verification_root()
        manifest = self._load_manifest(root)
        case = self._case(manifest, "EVAL-IAM-001")
        native = next(
            variant for variant in case["input_variants"] if variant["input_form"] == "native"
        )
        native["equivalence_group"] = None
        self._write_manifest(root, manifest)

        with self.assertRaisesRegex(EvaluationCorpusError, "equivalence group"):
            verify_corpus(root)

    def test_candidate_output_exposure_is_rejected(self):
        root = self._copy_verification_root()
        manifest = self._load_manifest(root)
        manifest["cases"][0]["provenance"]["candidate_output_seen"] = True
        self._write_manifest(root, manifest)

        with self.assertRaisesRegex(EvaluationCorpusError, "violates its JSON Schema"):
            verify_corpus(root)

    def test_wrong_module_contract_is_rejected(self):
        root = self._copy_verification_root()
        manifest = self._load_manifest(root)
        case = self._case(manifest, "EVAL-IAM-001")
        simplified = next(
            variant
            for variant in case["input_variants"]
            if variant["input_form"] == "simplified"
        )
        simplified["files"][0]["contract"] = (
            "schemas/storage-environment-v1.0.schema.json"
        )
        self._write_manifest(root, manifest)

        with self.assertRaisesRegex(EvaluationCorpusError, "wrong contract"):
            verify_corpus(root)

    def test_protocol_digest_tampering_is_rejected(self):
        root = self._copy_verification_root()
        manifest = self._load_manifest(root)
        manifest["protocol"]["sha256"] = "0" * 64
        self._write_manifest(root, manifest)

        with self.assertRaisesRegex(EvaluationCorpusError, "wrong protocol digest"):
            verify_corpus(root)

    def test_rule_catalog_tampering_is_rejected(self):
        root = self._copy_verification_root()
        catalog_path = root / "cloud_rules/rules-v1.0.json"
        with catalog_path.open("a", encoding="utf-8") as handle:
            handle.write("\n")

        with self.assertRaisesRegex(EvaluationCorpusError, "rule-catalog digest"):
            verify_corpus(root)

    def test_local_path_in_manifest_is_rejected(self):
        root = self._copy_verification_root()
        manifest = self._load_manifest(root)
        manifest["description"] = "Authored under /Users/example/private-workspace."
        self._write_manifest(root, manifest)

        with self.assertRaisesRegex(EvaluationCorpusError, "local-path pattern"):
            verify_corpus(root)

    def test_falsely_attributed_aws_reference_is_rejected(self):
        root = self._copy_verification_root()
        manifest = self._load_manifest(root)
        case = manifest["cases"][0]
        assertion_reference = case["assertions"][0]["authoritative_references"][0]
        original_url = assertion_reference["url"]
        forged_url = "https://example.com/not-an-aws-reference"
        assertion_reference["url"] = forged_url
        for reference in case["provenance"]["source_references"]:
            if reference["url"] == original_url:
                reference["url"] = forged_url
        self._write_manifest(root, manifest)

        with self.assertRaisesRegex(EvaluationCorpusError, "non-AWS reference host"):
            verify_corpus(root)

    def test_symlinked_evidence_is_rejected(self):
        root = self._copy_verification_root()
        manifest = self._load_manifest(root)
        evidence_path = root / manifest["cases"][0]["input_variants"][0]["files"][0][
            "path"
        ]
        target_path = evidence_path.with_suffix(".target")
        evidence_path.rename(target_path)
        try:
            evidence_path.symlink_to(target_path.name)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"Symlinks are unavailable: {error}")

        with self.assertRaisesRegex(EvaluationCorpusError, "traverses a symlink"):
            verify_corpus(root)


if __name__ == "__main__":
    unittest.main()
