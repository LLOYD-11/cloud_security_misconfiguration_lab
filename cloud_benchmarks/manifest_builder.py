"""Build a reviewable benchmark-manifest snapshot from curated profiles."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from cloud_benchmarks.models import (
    BENCHMARK_SCHEMA_VERSION,
    finding_signature_dicts,
)
from cloud_benchmarks.profiles import run_functional_profile
from cloud_rules import MODULE_ORDER, load_builtin_catalog

UNSUPPORTED_EVIDENCE = {
    "iam": [
        "Effective authorization across SCPs, RCPs, resource policies, session policies, and explicit denies is not fully modeled.",
        "Credential posture is limited to the supplied snapshot and does not prove credential compromise.",
    ],
    "storage": [
        "The offline bucket snapshot does not reproduce full IAM authorization or live S3 reachability.",
        "Organization policies, VPC endpoint policies, KMS key policies, and later configuration changes are outside the case.",
    ],
    "network": [
        "A security-group permission is not proof of end-to-end reachability without separate path evidence.",
        "Routes, network ACLs, public addresses, load balancers, and later topology changes are outside the case.",
    ],
    "cloudtrail": [
        "The event cases do not baseline approved administrative changes, user behavior, or source reputation.",
        "Missing log delivery, disabled trails, and activity outside the supplied time range cannot be inferred.",
    ],
}

MALFORMED_ERRORS = {
    "iam": (
        "ValueError",
        "AWS IAM authorization details are truncated; collect all pages before analysis.",
    ),
    "storage": (
        "ValueError",
        "AWS S3 evidence bundle must use schema_version '1.0'.",
    ),
    "network": (
        "ValueError",
        "DescribeSecurityGroups response is paginated; collect all pages before analysis.",
    ),
    "cloudtrail": (
        "ValueError",
        "CloudTrail log file 1 field Records must contain at least one event.",
    ),
}

SCALE_COUNTS = {
    "iam": {"small": 100, "large": 5_000},
    "storage": {"small": 100, "large": 5_000},
    "network": {"small": 100, "large": 5_000},
    "cloudtrail": {"small": 200, "large": 10_000},
}
SCALE_RULES = {
    "iam": "IAM-006",
    "storage": "STO-005",
    "network": "NET-001",
    "cloudtrail": "CLD-006",
}
SCALE_MEMORY_BUDGETS = {
    "small": 16 * 1024 * 1024,
    "large": 64 * 1024 * 1024,
}


def build_manifest() -> dict[str, Any]:
    """Create a snapshot whose expected findings require explicit review."""

    catalog = load_builtin_catalog()
    cases: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    rules_by_module = {
        module: [rule for rule in catalog.rules if rule.module == module]
        for module in MODULE_ORDER
    }

    for module in MODULE_ORDER:
        for rule in rules_by_module[module]:
            positive_id = f"{rule.rule_id}-positive"
            boundary_id = f"{rule.rule_id}-boundary"
            positive_profile = f"rule:{rule.rule_id}:positive"
            boundary_profile = f"rule:{rule.rule_id}:boundary"
            cases.extend(
                [
                    {
                        "id": positive_id,
                        "module": module,
                        "classification": "positive",
                        "profile": positive_profile,
                        "covers_rules": [rule.rule_id],
                        "description": (
                            f"Minimal deterministic evidence that exercises {rule.rule_id}."
                        ),
                        "expected_findings": finding_signature_dicts(
                            run_functional_profile(positive_profile)
                        ),
                        "false_positive_rationale": (
                            f"{rule.confidence_basis} The benchmark proves rule "
                            "matching, not that the observed condition is malicious."
                        ),
                        "unsupported_evidence": UNSUPPORTED_EVIDENCE[module],
                    },
                    {
                        "id": boundary_id,
                        "module": module,
                        "classification": "boundary",
                        "profile": boundary_profile,
                        "covers_rules": [rule.rule_id],
                        "description": (
                            f"Near-miss or exact-threshold evidence for {rule.rule_id}."
                        ),
                        "expected_findings": finding_signature_dicts(
                            run_functional_profile(boundary_profile)
                        ),
                        "false_positive_rationale": (
                            f"The profile isolates the decision boundary for "
                            f"{rule.rule_id}; companion findings remain explicit, "
                            "but this rule must not cross its documented boundary."
                        ),
                        "unsupported_evidence": UNSUPPORTED_EVIDENCE[module],
                    },
                ]
            )
            coverage.append(
                {
                    "rule_id": rule.rule_id,
                    "module": module,
                    "positive_case": positive_id,
                    "negative_case": f"{module}-hardened-negative",
                    "boundary_case": boundary_id,
                    "malformed_case": f"{module}-native-malformed",
                }
            )

        negative_profile = f"module:{module}:negative"
        cases.append(
            {
                "id": f"{module}-hardened-negative",
                "module": module,
                "classification": "negative",
                "profile": negative_profile,
                "covers_rules": [
                    rule.rule_id for rule in rules_by_module[module]
                ],
                "description": (
                    f"Hardened {module} baseline expected to produce no findings."
                ),
                "expected_findings": finding_signature_dicts(
                    run_functional_profile(negative_profile)
                ),
                "false_positive_rationale": (
                    "The profile contains intentionally safe evidence. Any finding "
                    "would be treated as an analyzer false positive or contract drift."
                ),
                "unsupported_evidence": UNSUPPORTED_EVIDENCE[module],
            }
        )
        error_type, error_message = MALFORMED_ERRORS[module]
        cases.append(
            {
                "id": f"{module}-native-malformed",
                "module": module,
                "classification": "malformed",
                "profile": f"module:{module}:malformed",
                "covers_rules": [
                    rule.rule_id for rule in rules_by_module[module]
                ],
                "description": (
                    f"Malformed or incomplete native {module} evidence must fail closed."
                ),
                "expected_error": {
                    "type": error_type,
                    "message": error_message,
                },
                "false_positive_rationale": (
                    "No security conclusion is allowed because malformed evidence is "
                    "rejected before analyzer findings are produced."
                ),
                "unsupported_evidence": UNSUPPORTED_EVIDENCE[module],
            }
        )

    scale_cases: list[dict[str, Any]] = []
    for module in MODULE_ORDER:
        for size in ("small", "large"):
            input_count = SCALE_COUNTS[module][size]
            expected_count = input_count // 10
            scale_cases.append(
                {
                    "id": f"{module}-{size}",
                    "module": module,
                    "size": size,
                    "input_count": input_count,
                    "expected_finding_count": expected_count,
                    "expected_rule_counts": {
                        SCALE_RULES[module]: expected_count
                    },
                    "max_findings_per_input": 0.1,
                    "max_peak_memory_bytes": SCALE_MEMORY_BUDGETS[size],
                }
            )

    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "catalog_schema_version": catalog.schema_version,
        "rule_count": len(catalog.rules),
        "case_count": len(cases),
        "scale_case_count": len(scale_cases),
        "acceptance_budgets": {
            "minimum_statement_coverage_percent": 90.0,
            "minimum_branch_coverage_percent": 85.0,
            "required_functional_pass_rate": 1.0,
            "required_malformed_rejection_rate": 1.0,
            "require_scale_determinism": True,
            "wall_clock_gate_enabled": False,
        },
        "cases": cases,
        "rule_coverage": coverage,
        "scale_cases": scale_cases,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Regenerate the benchmark expectation snapshot. Review every diff "
            "before committing it."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Manifest output path.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"Benchmark manifest: {manifest['case_count']} functional cases, "
        f"{manifest['scale_case_count']} scale cases -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
