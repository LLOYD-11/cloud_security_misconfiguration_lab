"""Build and verify the frozen M12 external-baseline artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from tools.evaluation_corpus import EvaluationCorpusError, verify_corpus

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = Path("evaluation/protocol-v1.0.json")
CORPUS_PATH = Path("evaluation/corpus-manifest-v1.0.json")
OVERLAP_PATH = Path("evaluation/baseline-overlap-v1.0.json")
OUTCOMES_PATH = Path("evaluation/baseline-outcomes-v1.0.json")
OVERLAP_SCHEMA_PATH = Path("schemas/evaluation-baseline-overlap-v1.0.schema.json")
OUTCOMES_SCHEMA_PATH = Path("schemas/evaluation-baseline-outcomes-v1.0.schema.json")

MATRIX_VERSION = "1.0.0"
OUTCOMES_VERSION = "1.0.0"
CREATED_ON = "2026-08-13"
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
PROWLER_COMMIT = "b21ddad32c6d9a98eb819f0ccadac8a6792c2837"
SIGMA_COMMIT = "552f3fee420ef232a8e5790c4fae591847e32347"
SIGMA_ASSET_SHA256 = "45ccbd62cbf0d7ccca6f44eaa010f86bb24f082b5411c5e22c71907e7770ee46"

BASELINE_BY_MODULE = {
    "iam": "prowler-aws",
    "storage": "prowler-aws",
    "network": "prowler-aws",
    "cloudtrail": "sigma-core",
}

PROWLER_SERVICE_BY_MODULE = {
    "iam": "iam",
    "storage": "s3",
    "network": "ec2",
}

PROWLER_TREE_URLS = {
    module: (
        "https://github.com/prowler-cloud/prowler/tree/"
        f"{PROWLER_COMMIT}/prowler/providers/aws/services/{service}"
    )
    for module, service in PROWLER_SERVICE_BY_MODULE.items()
}
SIGMA_TREE_URL = f"https://github.com/SigmaHQ/sigma/tree/{SIGMA_COMMIT}/rules/cloud/aws/cloudtrail"


class EvaluationBaselineError(ValueError):
    """Raised when baseline artifacts violate their frozen contracts."""


@dataclass(frozen=True)
class CheckRef:
    """A baseline check identity and immutable repository path."""

    check_id: str
    source_path: str


@dataclass(frozen=True)
class OverlapSpec:
    """One complete rule-level comparison classification."""

    lab_rule_id: str
    module: str
    relationship: str
    predicate_direction: str
    checks: tuple[CheckRef, ...]
    rationale: str
    semantic_differences: tuple[str, ...]


@dataclass(frozen=True)
class BaselineSummary:
    """Verified R3 matrix and source-audited baseline outcome counts."""

    rule_count: int
    exact_rule_count: int
    partial_rule_count: int
    no_counterpart_rule_count: int
    decision_count: int
    positive_prediction_count: int
    negative_prediction_count: int
    exclusion_count: int


def _prowler_check(module: str, check_id: str) -> CheckRef:
    service = PROWLER_SERVICE_BY_MODULE[module]
    return CheckRef(
        check_id=check_id,
        source_path=(f"prowler/providers/aws/services/{service}/{check_id}/{check_id}.py"),
    )


def _sigma_check(check_id: str, filename: str) -> CheckRef:
    return CheckRef(
        check_id=check_id,
        source_path=f"rules/cloud/aws/cloudtrail/{filename}",
    )


ADMIN_POLICY_CHECKS = tuple(
    _prowler_check("iam", check_id)
    for check_id in (
        "iam_aws_attached_policy_no_administrative_privileges",
        "iam_customer_attached_policy_no_administrative_privileges",
        "iam_customer_unattached_policy_no_administrative_privileges",
        "iam_inline_policy_no_administrative_privileges",
    )
)

FULL_SERVICE_CHECKS = tuple(
    _prowler_check("iam", check_id)
    for check_id in (
        "iam_policy_no_full_access_to_cloudtrail",
        "iam_policy_no_full_access_to_kms",
        "iam_inline_policy_no_full_access_to_cloudtrail",
        "iam_inline_policy_no_full_access_to_kms",
    )
)

NETWORK_SERVICE_CHECKS = tuple(
    _prowler_check("network", check_id)
    for check_id in (
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018",
    )
)


OVERLAP_SPECS = (
    OverlapSpec(
        "IAM-001",
        "iam",
        "partial",
        "incomparable",
        ADMIN_POLICY_CHECKS,
        "Both identify administrative policy breadth, but their decision units and policy algebra differ.",
        (
            "The lab requires one explicit Allow statement with Action and Resource both equal to a full wildcard.",
            "Prowler aggregates policy statements, recognizes alternate broad resource forms and NotAction, and reports policy resources rather than lab principals.",
        ),
    ),
    OverlapSpec(
        "IAM-002",
        "iam",
        "partial",
        "incomparable",
        ADMIN_POLICY_CHECKS + FULL_SERVICE_CHECKS,
        "Prowler has administrative and selected full-service checks related to wildcard actions.",
        (
            "The lab flags full, service-wide, and partial wildcard syntax for every AWS service without requiring Resource to be global.",
            "Prowler evaluates effective administrative or complete CloudTrail and KMS access on all resources, including policy combinations without a literal wildcard action.",
        ),
    ),
    OverlapSpec(
        "IAM-003",
        "iam",
        "partial",
        "incomparable",
        ADMIN_POLICY_CHECKS + FULL_SERVICE_CHECKS,
        "Prowler administrative and full-service checks also consider wildcard resource scope.",
        (
            "The lab flags any allowed action whose Resource is a full wildcard.",
            "Prowler requires administrative or selected full-service effective access and can aggregate multiple statements or NotAction constructs.",
        ),
    ),
    OverlapSpec(
        "IAM-004",
        "iam",
        "none",
        "no-counterpart",
        (),
        "No Prowler AWS 5.38.0 IAM check evaluates the lab's generic broad S3 write predicate.",
        ("The released provider has no directly comparable retained-evidence predicate.",),
    ),
    OverlapSpec(
        "IAM-005",
        "iam",
        "none",
        "no-counterpart",
        (),
        "Prowler MFA checks evaluate enrollment or administrator group posture, not an MFA condition on each sensitive allow statement.",
        ("No released check uses the same policy-condition evidence and decision unit.",),
    ),
    OverlapSpec(
        "IAM-006",
        "iam",
        "exact",
        "equivalent",
        (_prowler_check("iam", "iam_user_mfa_enabled_console_access"),),
        "Both fail a non-root IAM user when console-password access is enabled and MFA is inactive.",
        (),
    ),
    OverlapSpec(
        "IAM-007",
        "iam",
        "exact",
        "equivalent",
        (_prowler_check("iam", "iam_rotate_access_key_90_days"),),
        "Both fail an active IAM access key only when its age is greater than 90 days.",
        (),
    ),
    OverlapSpec(
        "IAM-008",
        "iam",
        "partial",
        "lab-broader",
        (
            _prowler_check("iam", "iam_role_cross_account_readonlyaccess_policy"),
            _prowler_check("iam", "iam_role_cross_service_confused_deputy_prevention"),
        ),
        "Prowler has narrower cross-account and confused-deputy role checks over related trust evidence.",
        (
            "The lab evaluates public or external principals for any assumable role and models several fixed-value guardrails.",
            "Prowler limits these checks to ReadOnlyAccess roles or service roles and applies different condition handling.",
        ),
    ),
    OverlapSpec(
        "IAM-009",
        "iam",
        "partial",
        "lab-broader",
        ADMIN_POLICY_CHECKS,
        "Prowler's administrative-policy helper interprets Allow NotAction on broad resources.",
        (
            "The lab reports every supported broad Allow NotAction complement, including cases that are not administrative.",
            "Prowler reports only when its aggregate administrative-access predicate is satisfied.",
        ),
    ),
    OverlapSpec(
        "IAM-010",
        "iam",
        "partial",
        "lab-broader",
        ADMIN_POLICY_CHECKS,
        "Prowler's administrative-policy helper interprets Allow NotResource in an administrative calculation.",
        (
            "The lab reports broad Allow NotResource statements even when they do not produce administrative access.",
            "Prowler requires its aggregate administrative-access predicate and supports different broad resource forms.",
        ),
    ),
    OverlapSpec(
        "IAM-011",
        "iam",
        "partial",
        "lab-narrower",
        (_prowler_check("iam", "iam_user_accesskey_unused"),),
        "Both detect unused active IAM access keys, but the frozen default thresholds differ.",
        (
            "The lab threshold is greater than 90 days.",
            "Prowler 5.38.0 defaults max_unused_access_keys_days to 45 days.",
        ),
    ),
    OverlapSpec(
        "IAM-012",
        "iam",
        "partial",
        "lab-narrower",
        (_prowler_check("iam", "iam_user_console_access_unused"),),
        "Both detect stale IAM console access, but the frozen default thresholds differ.",
        (
            "The lab threshold is greater than 90 days and uses retained credential-posture evidence.",
            "Prowler 5.38.0 defaults max_console_access_days to 45 days and reads collected user state.",
        ),
    ),
    OverlapSpec(
        "IAM-013",
        "iam",
        "exact",
        "equivalent",
        (_prowler_check("iam", "iam_no_root_access_key"),),
        "Both fail the root account when either root access-key slot is active.",
        (),
    ),
    OverlapSpec(
        "IAM-014",
        "iam",
        "partial",
        "lab-narrower",
        (_prowler_check("iam", "iam_root_mfa_enabled"),),
        "Both identify missing root MFA from credential-report evidence.",
        (
            "The lab requires an active root console password before reporting.",
            "Prowler evaluates root MFA whenever the root account has a password or active access key.",
        ),
    ),
    OverlapSpec(
        "IAM-015",
        "iam",
        "none",
        "no-counterpart",
        (),
        "No Prowler AWS 5.38.0 check evaluates whether a permissions-boundary document itself allows full wildcard access.",
        (
            "The provider collects boundary attachment metadata but has no equivalent boundary-document predicate.",
        ),
    ),
    OverlapSpec(
        "STO-001",
        "storage",
        "partial",
        "incomparable",
        (_prowler_check("storage", "s3_bucket_level_public_access_block"),),
        "Both assess S3 Block Public Access, but they require different controls and scopes.",
        (
            "The lab requires all four bucket-level booleans and does not apply an account-level fallback.",
            "Prowler checks IgnorePublicAcls and RestrictPublicBuckets and can pass from account-level settings.",
        ),
    ),
    OverlapSpec(
        "STO-002",
        "storage",
        "partial",
        "incomparable",
        (
            _prowler_check("storage", "s3_bucket_public_list_acl"),
            _prowler_check("storage", "s3_bucket_public_write_acl"),
        ),
        "Prowler has public read/list and write ACL checks over related grants.",
        (
            "The lab evaluates every public ACL permission and suppresses ineffective grants when IgnorePublicAcls or BucketOwnerEnforced applies.",
            "Prowler splits permissions across checks and can use account-level or selected bucket-level public-access settings.",
        ),
    ),
    OverlapSpec(
        "STO-003",
        "storage",
        "partial",
        "incomparable",
        (
            _prowler_check("storage", "s3_bucket_public_access"),
            _prowler_check("storage", "s3_bucket_policy_public_write_access"),
        ),
        "Prowler evaluates public bucket policies, including a separate public-write check.",
        (
            "The lab classifies modeled S3 public principals and fixed-value guardrails independently of Block Public Access enforcement.",
            "Prowler incorporates account and bucket public-access settings and applies a different public-policy helper and action scope.",
        ),
    ),
    OverlapSpec(
        "STO-004",
        "storage",
        "exact",
        "equivalent",
        (_prowler_check("storage", "s3_bucket_default_encryption"),),
        "Both fail when retained bucket evidence has no explicit default encryption configuration.",
        (),
    ),
    OverlapSpec(
        "STO-005",
        "storage",
        "exact",
        "equivalent",
        (_prowler_check("storage", "s3_bucket_object_versioning"),),
        "Both fail unless retained bucket versioning state is Enabled.",
        (),
    ),
    OverlapSpec(
        "STO-006",
        "storage",
        "partial",
        "lab-narrower",
        (_prowler_check("storage", "s3_bucket_acl_prohibited"),),
        "Both pass BucketOwnerEnforced and identify ACL-enabled Object Ownership modes.",
        (
            "The lab reports only explicit BucketOwnerPreferred or ObjectWriter evidence.",
            "Prowler also fails when Object Ownership evidence is absent or does not contain BucketOwnerEnforced.",
        ),
    ),
    OverlapSpec(
        "NET-001",
        "network",
        "partial",
        "lab-broader",
        NETWORK_SERVICE_CHECKS,
        "Prowler has individual checks for a subset of the lab's sensitive service ports.",
        (
            "The lab catalog contains additional administration, database, data-service, and control-plane ports and supports broad public CIDRs.",
            "Prowler's mapped checks use 0.0.0.0/0 or ::/0, are primarily TCP-specific, and apply provider resource-use filtering.",
        ),
    ),
    OverlapSpec(
        "NET-002",
        "network",
        "partial",
        "lab-broader",
        (_prowler_check("network", "ec2_securitygroup_allow_ingress_from_internet_to_all_ports"),),
        "Both identify all-port public ingress security-group rules.",
        (
            "The lab also recognizes explicit 0-65535 ranges, protocol aliases, and broad public CIDRs.",
            "Prowler requires all-protocol traffic from 0.0.0.0/0 or ::/0 and applies provider resource-use filtering.",
        ),
    ),
    OverlapSpec(
        "NET-003",
        "network",
        "none",
        "no-counterpart",
        (),
        "No Prowler AWS 5.38.0 EC2 check evaluates unrestricted public egress for every security group.",
        ("The default-security-group check has a different resource scope and predicate.",),
    ),
    OverlapSpec(
        "CLD-001",
        "cloudtrail",
        "none",
        "no-counterpart",
        (),
        "The frozen Sigma Core release asset contains no released AWS root-account-use rule.",
        (
            "A related repository rule exists outside the pinned release asset and is therefore out of scope.",
        ),
    ),
    OverlapSpec(
        "CLD-002",
        "cloudtrail",
        "none",
        "no-counterpart",
        (),
        "The frozen Sigma Core release asset contains no MFA-device deactivation or deletion rule.",
        ("No released selection covers the retained event names.",),
    ),
    OverlapSpec(
        "CLD-003",
        "cloudtrail",
        "none",
        "no-counterpart",
        (),
        "The frozen Sigma Core release asset contains no released security-group change rule.",
        (
            "A related repository rule exists outside the pinned release asset and is therefore out of scope.",
        ),
    ),
    OverlapSpec(
        "CLD-004",
        "cloudtrail",
        "none",
        "no-counterpart",
        (),
        "The frozen Sigma Core release asset contains no bucket policy, ACL, or Public Access Block change selection.",
        ("Released S3 rules use disjoint event names or additional tool-specific evidence.",),
    ),
    OverlapSpec(
        "CLD-005",
        "cloudtrail",
        "partial",
        "lab-broader",
        (
            _sigma_check(
                "db014773-7375-4f4e-b83b-133337c0ffee",
                "aws_iam_s3browser_templated_s3_bucket_policy_creation.yml",
            ),
        ),
        "The released Sigma rule includes PutUserPolicy but only for a specific S3 Browser template signature.",
        (
            "The lab detects seven IAM policy mutation event names without a user-agent or policy-template requirement.",
            "The Sigma selection is limited to PutUserPolicy with S3 Browser and three request-parameter substrings.",
        ),
    ),
    OverlapSpec(
        "CLD-006",
        "cloudtrail",
        "none",
        "no-counterpart",
        (),
        "The frozen Sigma Core release asset contains no actor-and-source sliding-window API failure rule.",
        (
            "Single-event authentication rules outside the release asset do not implement the registered threshold predicate.",
        ),
    ),
    OverlapSpec(
        "CLD-007",
        "cloudtrail",
        "none",
        "no-counterpart",
        (),
        "The frozen Sigma Core release asset contains no successful ConsoleLogin-without-MFA rule.",
        ("A related experimental repository rule is absent from the pinned release asset.",),
    ),
    OverlapSpec(
        "CLD-008",
        "cloudtrail",
        "partial",
        "incomparable",
        (
            _sigma_check(
                "db014773-d9d9-4792-91e5-133337c0ffee",
                "aws_iam_s3browser_user_or_accesskey_creation.yml",
            ),
            _sigma_check(
                "db014773-b1d3-46bd-ba26-133337c0ffee",
                "aws_iam_s3browser_loginprofile_creation.yml",
            ),
        ),
        "Two released Sigma rules overlap CreateAccessKey or CreateLoginProfile only for S3 Browser activity.",
        (
            "The lab covers five persistent credential event types without a user-agent condition.",
            "The Sigma rules add S3 Browser and extra event alternatives while omitting several lab credential types.",
        ),
    ),
    OverlapSpec(
        "CLD-009",
        "cloudtrail",
        "none",
        "no-counterpart",
        (),
        "The frozen Sigma Core release asset contains no UpdateAssumeRolePolicy selection.",
        ("No released rule covers the same role-trust mutation event.",),
    ),
    OverlapSpec(
        "CLD-010",
        "cloudtrail",
        "partial",
        "lab-broader",
        (
            _sigma_check(
                "07330162-dba1-4746-8121-a9647d49d297",
                "aws_config_disable_recording.yml",
            ),
        ),
        "The released Sigma AWS Config rule matches two events within the lab's broader defense-impairment set.",
        (
            "The lab also covers CloudTrail, GuardDuty, flow-log, Security Hub, and an additional AWS Config disable event.",
            "The Sigma selection is limited to DeleteDeliveryChannel and StopConfigurationRecorder.",
        ),
    ),
    OverlapSpec(
        "CLD-011",
        "cloudtrail",
        "none",
        "no-counterpart",
        (),
        "The frozen Sigma Core release asset contains no DisableKey or ScheduleKeyDeletion rule.",
        ("The released KMS rule concerns imported key material and uses disjoint events.",),
    ),
)


EXACT_SOURCE_PREDICATES = {
    "IAM-006": {
        "baseline_check_id": "iam_user_mfa_enabled_console_access",
        "source_path": "prowler/providers/aws/services/iam/iam_user_mfa_enabled_console_access/iam_user_mfa_enabled_console_access.py",
        "sha256": "4d0e89d92560c8e81a167524866d6f84eb23b7163736b7b22df59ac7ed653aff",
    },
    "IAM-007": {
        "baseline_check_id": "iam_rotate_access_key_90_days",
        "source_path": "prowler/providers/aws/services/iam/iam_rotate_access_key_90_days/iam_rotate_access_key_90_days.py",
        "sha256": "353e7e4bd0837f2e376dcaddfbce664a1cb70c5977db683a770cd1621be7fa6b",
    },
    "IAM-013": {
        "baseline_check_id": "iam_no_root_access_key",
        "source_path": "prowler/providers/aws/services/iam/iam_no_root_access_key/iam_no_root_access_key.py",
        "sha256": "354dc5b14bb85eaa62f98af69a8bcbd109246240d61c4d0eb03524b8ae94d2c5",
    },
    "STO-004": {
        "baseline_check_id": "s3_bucket_default_encryption",
        "source_path": "prowler/providers/aws/services/s3/s3_bucket_default_encryption/s3_bucket_default_encryption.py",
        "sha256": "56099ab4219c92c9c41c13e047bba758071373f0dbd6ead75d3de13abe436130",
    },
    "STO-005": {
        "baseline_check_id": "s3_bucket_object_versioning",
        "source_path": "prowler/providers/aws/services/s3/s3_bucket_object_versioning/s3_bucket_object_versioning.py",
        "sha256": "4af640e1f646823133d13c6c06a95c4f352dd9f8f62497eacf1b3b7f1dd752f3",
    },
}

SIGMA_RELEASE_INVENTORY = (
    (
        "aws_cloudtrail_imds_malicious_usage.yml",
        "b070399db57d212727d7f7873c642a0c1da0930c2b45a5fe8945c3e2474caf37",
    ),
    (
        "aws_cloudtrail_ssm_malicious_usage.yml",
        "3d394a4a27a2af7c93034177c376f0358e13b29999074dda031334b7c92b2cc9",
    ),
    (
        "aws_config_disable_recording.yml",
        "d53eb7e1c2b87a31bd7ca7558f3eda1d15ceb4646451e8e0405d78618480aea6",
    ),
    (
        "aws_ec2_startup_script_change.yml",
        "8b58ce7431b1b3964cf0239c95164d92c9ce51c941101f70d901f7ff3b71b727",
    ),
    (
        "aws_guardduty_disruption.yml",
        "b82f5f5ef3080814b9bbf019a07f7ddf0313afd1e08b8eca3e5331b6bbf3a01c",
    ),
    (
        "aws_iam_s3browser_loginprofile_creation.yml",
        "981a9406ac25d4b00b2dfd446c87a14b3f22cc03f54f03c7b6229a3ac507c371",
    ),
    (
        "aws_iam_s3browser_templated_s3_bucket_policy_creation.yml",
        "f2a68159a3037c9511c3c74d3d027fc367dc9c4662df6c6f03723554aa92d245",
    ),
    (
        "aws_iam_s3browser_user_or_accesskey_creation.yml",
        "c566f779298d219eb9733ec7db1e554ff269f748f71b3fffd4eb9ff09adf53fe",
    ),
    (
        "aws_rds_public_db_restore.yml",
        "b15f0a86150e455237cd494602cd4305a500afbf1ebd61a4164129d665cafcbe",
    ),
    (
        "aws_securityhub_finding_evasion.yml",
        "865044229606ad4a1bc676f90a7c5edb0de04a5b9f518b69888648aee3480e91",
    ),
    ("aws_sso_idp_change.yml", "7ea2c37b143dacc7c240f87d69212a325155090b3535baa33ba38e8a7f58f145"),
    (
        "aws_update_login_profile.yml",
        "d29c571268666e01c24c0f3492b7fc04ccb66b165294c79c3b9afac57db80af6",
    ),
)


def _read_bytes(path: Path, *, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise EvaluationBaselineError(f"{label} must be a regular file: {path}.")
    with path.open("rb") as handle:
        content = handle.read(MAX_ARTIFACT_BYTES + 1)
    if len(content) > MAX_ARTIFACT_BYTES:
        raise EvaluationBaselineError(
            f"{label} exceeds the {MAX_ARTIFACT_BYTES:,}-byte limit: {path}."
        )
    return content


def _load_json(path: Path, *, label: str) -> Any:
    try:
        return json.loads(_read_bytes(path, label=label))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvaluationBaselineError(f"{label} is not valid UTF-8 JSON: {path}.") from error


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=False) + "\n").encode("utf-8")


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(_read_bytes(path, label="Artifact"))


def _artifact(root: Path, path: Path, version: str) -> dict[str, str]:
    return {
        "path": path.as_posix(),
        "version": version,
        "sha256": _sha256_file(root / path),
    }


def _source_url(baseline_id: str, source_path: str) -> str:
    if baseline_id == "prowler-aws":
        return f"https://github.com/prowler-cloud/prowler/blob/{PROWLER_COMMIT}/{source_path}"
    return f"https://github.com/SigmaHQ/sigma/blob/{SIGMA_COMMIT}/{source_path}"


def _baseline_snapshots(protocol: dict[str, Any]) -> list[dict[str, Any]]:
    snapshots: list[dict[str, Any]] = []
    for baseline in protocol["external_baselines"]:
        snapshot = {
            "id": baseline["id"],
            "version": baseline["version"],
            "commit_sha": baseline["commit_sha"],
            "source_url": baseline["source_url"],
        }
        release_asset = baseline.get("release_asset")
        if release_asset is not None:
            snapshot["release_asset_sha256"] = release_asset["sha256"]
        snapshots.append(snapshot)
    return snapshots


def _validate_spec_inventory(catalog: dict[str, Any]) -> None:
    catalog_pairs = [(str(rule["rule_id"]), str(rule["module"])) for rule in catalog["rules"]]
    spec_pairs = [(spec.lab_rule_id, spec.module) for spec in OVERLAP_SPECS]
    if spec_pairs != catalog_pairs:
        raise EvaluationBaselineError(
            "Overlap specs must cover the rule catalog exactly and in catalog order."
        )

    seen_check_paths: dict[tuple[str, str], str] = {}
    for spec in OVERLAP_SPECS:
        expected_baseline = BASELINE_BY_MODULE.get(spec.module)
        if expected_baseline is None:
            raise EvaluationBaselineError(f"Unknown module in overlap specs: {spec.module}.")
        if spec.relationship == "exact":
            if spec.predicate_direction != "equivalent" or spec.semantic_differences:
                raise EvaluationBaselineError(
                    f"Exact overlap {spec.lab_rule_id} must be equivalent without differences."
                )
            if spec.lab_rule_id not in EXACT_SOURCE_PREDICATES:
                raise EvaluationBaselineError(
                    f"Exact overlap {spec.lab_rule_id} has no replay source predicate."
                )
        elif spec.lab_rule_id in EXACT_SOURCE_PREDICATES:
            raise EvaluationBaselineError(
                f"Non-exact overlap {spec.lab_rule_id} has an exact replay predicate."
            )
        if spec.relationship == "none" and spec.checks:
            raise EvaluationBaselineError(
                f"No-counterpart overlap {spec.lab_rule_id} declares baseline checks."
            )
        if spec.relationship != "none" and not spec.checks:
            raise EvaluationBaselineError(
                f"Mapped overlap {spec.lab_rule_id} declares no baseline checks."
            )
        for check in spec.checks:
            key = (expected_baseline, check.check_id)
            prior = seen_check_paths.setdefault(key, check.source_path)
            if prior != check.source_path:
                raise EvaluationBaselineError(
                    f"Baseline check {check.check_id} has inconsistent source paths."
                )

    exact_rules = {spec.lab_rule_id for spec in OVERLAP_SPECS if spec.relationship == "exact"}
    if exact_rules != set(EXACT_SOURCE_PREDICATES):
        raise EvaluationBaselineError("Exact overlap and replay predicate inventories differ.")


def build_overlap_matrix(root: Path = PROJECT_ROOT) -> dict[str, Any]:
    """Build the complete immutable-source overlap matrix without candidate code."""

    root = root.resolve(strict=True)
    protocol = _load_json(root / PROTOCOL_PATH, label="Evaluation protocol")
    corpus = _load_json(root / CORPUS_PATH, label="Evaluation corpus manifest")
    catalog = _load_json(root / "cloud_rules/rules-v1.0.json", label="Rule catalog")
    _validate_spec_inventory(catalog)

    rows: list[dict[str, Any]] = []
    for spec in OVERLAP_SPECS:
        baseline_id = BASELINE_BY_MODULE[spec.module]
        source_urls = [_source_url(baseline_id, check.source_path) for check in spec.checks]
        if not source_urls:
            source_urls = [
                SIGMA_TREE_URL if baseline_id == "sigma-core" else PROWLER_TREE_URLS[spec.module]
            ]
        rows.append(
            {
                "lab_rule_id": spec.lab_rule_id,
                "module": spec.module,
                "baseline_id": baseline_id,
                "baseline_check_ids": [check.check_id for check in spec.checks],
                "relationship": spec.relationship,
                "predicate_direction": spec.predicate_direction,
                "comparison_eligible": spec.relationship == "exact",
                "source_urls": source_urls,
                "rationale": spec.rationale,
                "semantic_differences": list(spec.semantic_differences),
            }
        )

    return {
        "schema_version": "1.0",
        "matrix_id": "cloud-security-baseline-overlap",
        "matrix_version": MATRIX_VERSION,
        "created_on": CREATED_ON,
        "protocol": _artifact(
            root,
            PROTOCOL_PATH,
            str(protocol["protocol_version"]),
        ),
        "corpus": _artifact(
            root,
            CORPUS_PATH,
            str(corpus["corpus_version"]),
        ),
        "rule_count": len(catalog["rules"]),
        "baseline_snapshots": _baseline_snapshots(protocol),
        "comparison_policy": (
            "Only exact, equivalent rule-level predicates over retained evidence produce "
            "baseline decisions for later agreement metrics. Partial mappings are qualitative, "
            "and missing released scope is not a disagreement."
        ),
        "rows": rows,
    }


def _named_resource(
    values: Any,
    resource_id: str,
    *,
    collection: str,
) -> dict[str, Any]:
    if not isinstance(values, list):
        raise EvaluationBaselineError(f"Simplified evidence {collection} must be an array.")
    matches = [
        value for value in values if isinstance(value, dict) and value.get("name") == resource_id
    ]
    if len(matches) != 1:
        raise EvaluationBaselineError(
            f"Expected one {collection} resource {resource_id!r}, found {len(matches)}."
        )
    return matches[0]


def _active_key(key: Any) -> bool:
    return isinstance(key, dict) and str(key.get("status", "")).lower() == "active"


def _evaluate_iam_006(
    resource_type: str,
    resource_id: str,
    evidence: dict[str, Any],
) -> tuple[bool, str]:
    if resource_type != "user":
        raise EvaluationBaselineError("IAM-006 baseline decisions require a user resource.")
    user = _named_resource(evidence.get("users"), resource_id, collection="users")
    prediction = user.get("password_enabled") is True and user.get("mfa_enabled") is False
    return prediction, "Console password is enabled and MFA is explicitly inactive."


def _evaluate_iam_007(
    resource_type: str,
    resource_id: str,
    evidence: dict[str, Any],
) -> tuple[bool, str]:
    if resource_type != "user":
        raise EvaluationBaselineError("IAM-007 baseline decisions require a user resource.")
    user = _named_resource(evidence.get("users"), resource_id, collection="users")
    keys = user.get("access_keys")
    if not isinstance(keys, list):
        raise EvaluationBaselineError("IAM access_keys evidence must be an array.")
    prediction = any(
        _active_key(key) and isinstance(key.get("age_days"), int) and key["age_days"] > 90
        for key in keys
        if isinstance(key, dict)
    )
    return prediction, "At least one active access key has age_days greater than 90."


def _evaluate_iam_013(
    resource_type: str,
    resource_id: str,
    evidence: dict[str, Any],
) -> tuple[bool, str]:
    if resource_type != "root-account" or resource_id != "root":
        raise EvaluationBaselineError("IAM-013 baseline decisions require root-account/root.")
    root_account = evidence.get("root_account")
    if not isinstance(root_account, dict):
        raise EvaluationBaselineError("Simplified IAM evidence must contain root_account.")
    keys = root_account.get("access_keys")
    if not isinstance(keys, list):
        raise EvaluationBaselineError("Root access_keys evidence must be an array.")
    prediction = any(_active_key(key) for key in keys)
    return prediction, "At least one root-account access key is active."


def _storage_bucket(
    resource_type: str,
    resource_id: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    if resource_type != "bucket":
        raise EvaluationBaselineError("Storage baseline decisions require a bucket resource.")
    return _named_resource(evidence.get("buckets"), resource_id, collection="buckets")


def _evaluate_sto_004(
    resource_type: str,
    resource_id: str,
    evidence: dict[str, Any],
) -> tuple[bool, str]:
    bucket = _storage_bucket(resource_type, resource_id, evidence)
    encryption = bucket.get("encryption")
    enabled = encryption.get("enabled") if isinstance(encryption, dict) else None
    return enabled is not True, "Explicit bucket default-encryption enabled state is not true."


def _evaluate_sto_005(
    resource_type: str,
    resource_id: str,
    evidence: dict[str, Any],
) -> tuple[bool, str]:
    bucket = _storage_bucket(resource_type, resource_id, evidence)
    versioning = bucket.get("versioning")
    status = versioning.get("status") if isinstance(versioning, dict) else None
    return str(status).lower() != "enabled", "Bucket versioning status is not Enabled."


ExactEvaluator = Callable[[str, str, dict[str, Any]], tuple[bool, str]]

EXACT_EVALUATORS: dict[str, ExactEvaluator] = {
    "IAM-006": _evaluate_iam_006,
    "IAM-007": _evaluate_iam_007,
    "IAM-013": _evaluate_iam_013,
    "STO-004": _evaluate_sto_004,
    "STO-005": _evaluate_sto_005,
}


def _simplified_evidence(
    root: Path,
    case: dict[str, Any],
) -> tuple[dict[str, Any], str, list[dict[str, str]]]:
    variants = [
        variant for variant in case["input_variants"] if variant["input_form"] == "simplified"
    ]
    if len(variants) != 1:
        raise EvaluationBaselineError(
            f"Case {case['id']} must declare exactly one simplified input variant."
        )
    variant = variants[0]
    files = variant["files"]
    if len(files) != 1 or files[0]["media_type"] != "application/json":
        raise EvaluationBaselineError(
            f"Case {case['id']} simplified baseline evidence must be one JSON file."
        )
    record = files[0]
    path = root / str(record["path"])
    if _sha256_file(path) != record["sha256"]:
        raise EvaluationBaselineError(f"Simplified evidence digest mismatch for case {case['id']}.")
    evidence = _load_json(path, label=f"Simplified evidence for {case['id']}")
    if not isinstance(evidence, dict):
        raise EvaluationBaselineError(
            f"Simplified evidence for case {case['id']} must be an object."
        )
    evidence_files = [{"path": record["path"], "sha256": record["sha256"]}]
    return evidence, str(variant["id"]), evidence_files


def _source_predicate_records() -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for rule_id in sorted(EXACT_SOURCE_PREDICATES):
        source = EXACT_SOURCE_PREDICATES[rule_id]
        records.append(
            {
                "lab_rule_id": rule_id,
                "baseline_check_id": source["baseline_check_id"],
                "source_path": source["source_path"],
                "source_url": _source_url("prowler-aws", source["source_path"]),
                "sha256": source["sha256"],
            }
        )
    return records


def _sigma_release_inventory_records() -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for filename, digest in SIGMA_RELEASE_INVENTORY:
        source_path = f"rules/cloud/aws/cloudtrail/{filename}"
        records.append(
            {
                "source_path": source_path,
                "source_url": _source_url("sigma-core", source_path),
                "sha256": digest,
            }
        )
    return records


def _exclusion(
    case: dict[str, Any],
    assertion: dict[str, Any],
    row: dict[str, Any],
) -> dict[str, Any]:
    if not case["baseline_eligible"]:
        reason = "case-ineligible"
        explanation = (
            "The corpus marks this ambiguous case ineligible for baseline agreement; "
            "the retained assertion remains visible."
        )
    elif row["relationship"] == "partial":
        reason = "partial-overlap"
        explanation = (
            "The rule-level predicates are only partially related, so this decision is "
            "excluded from agreement metrics."
        )
    elif row["relationship"] == "none":
        reason = "no-counterpart"
        explanation = (
            "The pinned released baseline has no directly comparable rule-level predicate."
        )
    else:
        raise EvaluationBaselineError(
            f"Exact eligible assertion {assertion['id']} cannot be excluded."
        )
    return {
        "case_id": case["id"],
        "assertion_id": assertion["id"],
        "module": case["module"],
        "lab_rule_id": assertion["rule_id"],
        "resource_type": assertion["resource_type"],
        "resource_id": assertion["resource_id"],
        "baseline_id": row["baseline_id"],
        "relationship": row["relationship"],
        "reason": reason,
        "explanation": explanation,
    }


def build_baseline_outcomes(
    root: Path,
    overlap_matrix: dict[str, Any],
) -> dict[str, Any]:
    """Replay exact pinned predicates over retained simplified evidence only."""

    root = root.resolve(strict=True)
    protocol = _load_json(root / PROTOCOL_PATH, label="Evaluation protocol")
    corpus = _load_json(root / CORPUS_PATH, label="Evaluation corpus manifest")
    rows = {row["lab_rule_id"]: row for row in overlap_matrix["rows"]}
    decisions: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []

    for case in corpus["cases"]:
        evidence: dict[str, Any] | None = None
        variant_id = ""
        evidence_files: list[dict[str, str]] = []
        for assertion in case["assertions"]:
            rule_id = str(assertion["rule_id"])
            row = rows.get(rule_id)
            if row is None:
                raise EvaluationBaselineError(
                    f"Assertion {assertion['id']} references an unmapped rule {rule_id}."
                )
            if not case["baseline_eligible"] or row["relationship"] != "exact":
                exclusions.append(_exclusion(case, assertion, row))
                continue

            evaluator = EXACT_EVALUATORS.get(rule_id)
            if evaluator is None:
                raise EvaluationBaselineError(
                    f"Exact overlap {rule_id} has no independent replay evaluator."
                )
            if evidence is None:
                evidence, variant_id, evidence_files = _simplified_evidence(root, case)
            prediction, basis = evaluator(
                str(assertion["resource_type"]),
                str(assertion["resource_id"]),
                evidence,
            )
            decisions.append(
                {
                    "case_id": case["id"],
                    "assertion_id": assertion["id"],
                    "module": case["module"],
                    "lab_rule_id": rule_id,
                    "resource_type": assertion["resource_type"],
                    "resource_id": assertion["resource_id"],
                    "baseline_id": row["baseline_id"],
                    "baseline_check_ids": row["baseline_check_ids"],
                    "input_variant_id": variant_id,
                    "evidence_files": evidence_files,
                    "prediction": prediction,
                    "basis": basis,
                }
            )

    relationship_counts = Counter(row["relationship"] for row in overlap_matrix["rows"])
    prediction_counts = Counter(decision["prediction"] for decision in decisions)
    baseline_protocol = {baseline["id"]: baseline for baseline in protocol["external_baselines"]}
    baseline_runs: list[dict[str, Any]] = []
    for baseline_id in ("prowler-aws", "sigma-core"):
        baseline_decisions = [
            decision for decision in decisions if decision["baseline_id"] == baseline_id
        ]
        baseline_exclusions = [
            exclusion for exclusion in exclusions if exclusion["baseline_id"] == baseline_id
        ]
        exact_rule_count = sum(
            row["baseline_id"] == baseline_id and row["relationship"] == "exact"
            for row in overlap_matrix["rows"]
        )
        baseline = baseline_protocol[baseline_id]
        if baseline_id == "prowler-aws":
            source_predicates = _source_predicate_records()
            release_inventory: list[dict[str, str]] = []
            execution_mode = "source-audited-predicate-replay"
            notes = (
                "The full Prowler CLI was not run against a live account. Exact 5.38.0 "
                "check predicates were independently replayed over equivalent retained fields, "
                "with source paths and file digests preserved."
            )
        else:
            source_predicates = []
            release_inventory = _sigma_release_inventory_records()
            execution_mode = "no-exact-overlap"
            notes = (
                "The verified r2026-07-01 sigma_core.zip asset contains no released rule "
                "whose complete predicate is equivalent to a lab CloudTrail rule, so no Sigma "
                "decision is eligible for agreement scoring."
            )
        baseline_runs.append(
            {
                "baseline_id": baseline_id,
                "version": baseline["version"],
                "commit_sha": baseline["commit_sha"],
                "execution_mode": execution_mode,
                "upstream_tool_executed": False,
                "exact_rule_count": exact_rule_count,
                "decision_count": len(baseline_decisions),
                "positive_prediction_count": sum(
                    decision["prediction"] is True for decision in baseline_decisions
                ),
                "negative_prediction_count": sum(
                    decision["prediction"] is False for decision in baseline_decisions
                ),
                "exclusion_count": len(baseline_exclusions),
                "source_predicates": source_predicates,
                "release_inventory": release_inventory,
                "notes": notes,
            }
        )

    return {
        "schema_version": "1.0",
        "outcomes_id": "cloud-security-baseline-outcomes",
        "outcomes_version": OUTCOMES_VERSION,
        "status": "frozen",
        "created_on": CREATED_ON,
        "protocol": _artifact(
            root,
            PROTOCOL_PATH,
            str(protocol["protocol_version"]),
        ),
        "corpus": _artifact(
            root,
            CORPUS_PATH,
            str(corpus["corpus_version"]),
        ),
        "overlap_matrix": {
            "path": OVERLAP_PATH.as_posix(),
            "version": str(overlap_matrix["matrix_version"]),
            "sha256": _sha256_bytes(_json_bytes(overlap_matrix)),
        },
        "method": {
            "type": "source-audited-predicate-replay",
            "candidate_executed": False,
            "candidate_imported": False,
            "truth_labels_consumed": False,
            "input_variant_policy": "one-declared-simplified-variant-per-case",
            "statement": (
                "Only rule-level exact mappings are replayed. The runner reads decision-key "
                "identity and retained evidence but never reads assertion labels, expected "
                "severity, or candidate output."
            ),
        },
        "baseline_runs": baseline_runs,
        "summary": {
            "corpus_case_count": len(corpus["cases"]),
            "corpus_assertion_count": sum(len(case["assertions"]) for case in corpus["cases"]),
            "baseline_eligible_case_count": sum(
                case["baseline_eligible"] is True for case in corpus["cases"]
            ),
            "exact_rule_count": relationship_counts["exact"],
            "partial_rule_count": relationship_counts["partial"],
            "no_counterpart_rule_count": relationship_counts["none"],
            "decision_count": len(decisions),
            "positive_prediction_count": prediction_counts[True],
            "negative_prediction_count": prediction_counts[False],
            "exclusion_count": len(exclusions),
        },
        "decisions": decisions,
        "exclusions": exclusions,
    }


def _schema_error_message(error: Any) -> str:
    location = "/".join(str(value) for value in error.absolute_path) or "<root>"
    return f"{location}: {error.message}"


def _validate_schema(instance: Any, schema: Any, *, label: str) -> None:
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        raise EvaluationBaselineError(f"Invalid JSON Schema for {label}: {error}") from error
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(instance),
        key=lambda error: tuple(str(value) for value in error.absolute_path),
    )
    if errors:
        raise EvaluationBaselineError(
            f"{label} violates its JSON Schema: {_schema_error_message(errors[0])}"
        )


def _decision_key(record: dict[str, Any]) -> tuple[str, str]:
    return str(record["case_id"]), str(record["assertion_id"])


def _validate_outcome_partition(
    corpus: dict[str, Any],
    overlap_matrix: dict[str, Any],
    outcomes: dict[str, Any],
) -> None:
    expected_keys = {
        (str(case["id"]), str(assertion["id"]))
        for case in corpus["cases"]
        for assertion in case["assertions"]
    }
    decision_keys = [_decision_key(record) for record in outcomes["decisions"]]
    exclusion_keys = [_decision_key(record) for record in outcomes["exclusions"]]
    all_keys = decision_keys + exclusion_keys
    if len(all_keys) != len(set(all_keys)):
        raise EvaluationBaselineError("Baseline decisions and exclusions contain duplicates.")
    if set(all_keys) != expected_keys:
        raise EvaluationBaselineError(
            "Baseline decisions and exclusions do not partition every corpus assertion."
        )

    rows = {row["lab_rule_id"]: row for row in overlap_matrix["rows"]}
    cases = {case["id"]: case for case in corpus["cases"]}
    for decision in outcomes["decisions"]:
        row = rows[decision["lab_rule_id"]]
        case = cases[decision["case_id"]]
        if row["relationship"] != "exact" or row["comparison_eligible"] is not True:
            raise EvaluationBaselineError(
                f"Decision {decision['assertion_id']} is not backed by exact overlap."
            )
        if case["baseline_eligible"] is not True:
            raise EvaluationBaselineError(
                f"Decision {decision['assertion_id']} comes from an ineligible case."
            )
        if decision["baseline_check_ids"] != row["baseline_check_ids"]:
            raise EvaluationBaselineError(
                f"Decision {decision['assertion_id']} has the wrong baseline check IDs."
            )

    forbidden_keys = {"truth_label", "expected_severity", "candidate_prediction"}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            overlap = forbidden_keys.intersection(value)
            if overlap:
                raise EvaluationBaselineError(
                    f"Baseline outcomes expose forbidden truth or candidate fields: {sorted(overlap)}."
                )
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(outcomes)


def _summary_from(outcomes: dict[str, Any]) -> BaselineSummary:
    summary = outcomes["summary"]
    return BaselineSummary(
        rule_count=(
            summary["exact_rule_count"]
            + summary["partial_rule_count"]
            + summary["no_counterpart_rule_count"]
        ),
        exact_rule_count=summary["exact_rule_count"],
        partial_rule_count=summary["partial_rule_count"],
        no_counterpart_rule_count=summary["no_counterpart_rule_count"],
        decision_count=summary["decision_count"],
        positive_prediction_count=summary["positive_prediction_count"],
        negative_prediction_count=summary["negative_prediction_count"],
        exclusion_count=summary["exclusion_count"],
    )


def verify_baseline_artifacts(
    root: Path = PROJECT_ROOT,
    overlap_path: Path = OVERLAP_PATH,
    outcomes_path: Path = OUTCOMES_PATH,
) -> BaselineSummary:
    """Verify schemas, provenance, completeness, replay, and exact artifact bytes."""

    root = root.resolve(strict=True)
    try:
        verify_corpus(root, CORPUS_PATH)
    except EvaluationCorpusError as error:
        raise EvaluationBaselineError(f"Frozen corpus verification failed: {error}") from error

    overlap_file = overlap_path if overlap_path.is_absolute() else root / overlap_path
    outcomes_file = outcomes_path if outcomes_path.is_absolute() else root / outcomes_path
    overlap_matrix = _load_json(overlap_file, label="Baseline overlap matrix")
    outcomes = _load_json(outcomes_file, label="Baseline outcomes")
    overlap_schema = _load_json(root / OVERLAP_SCHEMA_PATH, label="Overlap schema")
    outcomes_schema = _load_json(root / OUTCOMES_SCHEMA_PATH, label="Outcomes schema")
    _validate_schema(overlap_matrix, overlap_schema, label="Baseline overlap matrix")
    _validate_schema(outcomes, outcomes_schema, label="Baseline outcomes")

    expected_overlap = build_overlap_matrix(root)
    if overlap_matrix != expected_overlap:
        raise EvaluationBaselineError(
            "Committed overlap matrix differs from the complete source-audited mapping."
        )
    if _read_bytes(overlap_file, label="Baseline overlap matrix") != _json_bytes(
        expected_overlap
    ):
        raise EvaluationBaselineError(
            "Committed overlap matrix is not encoded as canonical deterministic JSON."
        )
    expected_outcomes = build_baseline_outcomes(root, overlap_matrix)
    if outcomes != expected_outcomes:
        raise EvaluationBaselineError(
            "Committed baseline outcomes differ from deterministic predicate replay."
        )
    if _read_bytes(outcomes_file, label="Baseline outcomes") != _json_bytes(
        expected_outcomes
    ):
        raise EvaluationBaselineError(
            "Committed baseline outcomes are not encoded as canonical deterministic JSON."
        )

    corpus = _load_json(root / CORPUS_PATH, label="Evaluation corpus manifest")
    _validate_outcome_partition(corpus, overlap_matrix, outcomes)
    if outcomes["overlap_matrix"]["sha256"] != _sha256_file(overlap_file):
        raise EvaluationBaselineError("Baseline outcomes reference the wrong overlap digest.")
    if overlap_matrix["baseline_snapshots"][1]["release_asset_sha256"] != SIGMA_ASSET_SHA256:
        raise EvaluationBaselineError("Sigma release asset digest does not match the protocol.")
    return _summary_from(outcomes)


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def write_baseline_artifacts(root: Path = PROJECT_ROOT) -> BaselineSummary:
    """Generate the frozen matrix first, then bind replay outcomes to its digest."""

    root = root.resolve(strict=True)
    try:
        verify_corpus(root, CORPUS_PATH)
    except EvaluationCorpusError as error:
        raise EvaluationBaselineError(f"Frozen corpus verification failed: {error}") from error

    overlap_matrix = build_overlap_matrix(root)
    overlap_schema = _load_json(root / OVERLAP_SCHEMA_PATH, label="Overlap schema")
    _validate_schema(overlap_matrix, overlap_schema, label="Baseline overlap matrix")
    overlap_content = _json_bytes(overlap_matrix)
    _atomic_write(root / OVERLAP_PATH, overlap_content)

    outcomes = build_baseline_outcomes(root, overlap_matrix)
    outcomes_schema = _load_json(root / OUTCOMES_SCHEMA_PATH, label="Outcomes schema")
    _validate_schema(outcomes, outcomes_schema, label="Baseline outcomes")
    _atomic_write(root / OUTCOMES_PATH, _json_bytes(outcomes))
    return verify_baseline_artifacts(root)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build or verify the frozen M12 baseline overlap matrix and independent "
            "source-audited predicate outcomes without executing candidate analyzers."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=PROJECT_ROOT,
        help="Repository root containing evaluation, schemas, tools, and cloud_rules.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Regenerate the two committed R3 artifacts before verifying them.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        summary = (
            write_baseline_artifacts(args.root)
            if args.write
            else verify_baseline_artifacts(args.root)
        )
    except (OSError, EvaluationBaselineError) as error:
        print(f"Evaluation baseline verification failed: {error}")
        return 1
    print(
        "Evaluation baselines verified: "
        f"{summary.rule_count} rules "
        f"({summary.exact_rule_count} exact, "
        f"{summary.partial_rule_count} partial, "
        f"{summary.no_counterpart_rule_count} none), "
        f"{summary.decision_count} decisions "
        f"({summary.positive_prediction_count} positive, "
        f"{summary.negative_prediction_count} negative), "
        f"{summary.exclusion_count} exclusions."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
