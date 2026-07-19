"""Normalize native AWS S3 API evidence into the storage analyzer contract."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cloud_analysis import SkippedEvidence
from cloud_inputs import (
    enforce_collection_limit,
    load_bounded_json,
    parse_bounded_json_text,
    validate_analysis_input_limits,
    validate_json_value_limits,
)

ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
SCHEMA_VERSION = "1.0"
PAB_FIELDS = {
    "BlockPublicAcls": "block_public_acls",
    "IgnorePublicAcls": "ignore_public_acls",
    "BlockPublicPolicy": "block_public_policy",
    "RestrictPublicBuckets": "restrict_public_buckets",
}
NO_PUBLIC_ACCESS_BLOCK = "NoSuchPublicAccessBlockConfiguration"
NO_BUCKET_POLICY = "NoSuchBucketPolicy"
NO_OWNERSHIP_CONTROLS = "OwnershipControlsNotFoundError"
OBJECT_OWNERSHIP_VALUES = {
    "BucketOwnerEnforced",
    "BucketOwnerPreferred",
    "ObjectWriter",
}


@dataclass(frozen=True)
class S3NormalizationResult:
    """Normalized storage input plus non-fatal evidence-quality warnings."""

    environment: dict[str, Any]
    warnings: tuple[str, ...]
    skipped_evidence: tuple[SkippedEvidence, ...] = ()


def _load_json_object(path: Path) -> dict[str, Any]:
    payload = load_bounded_json(
        path,
        label=f"AWS S3 evidence bundle {path}",
    )
    if not isinstance(payload, dict):
        raise ValueError("AWS S3 evidence bundle must contain a JSON object.")
    return payload


def _required_object(payload: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{context} field {key} must be an object.")
    return value


def _required_object_list(
    payload: dict[str, Any],
    key: str,
    context: str,
) -> list[dict[str, Any]]:
    value = payload.get(key)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{context} field {key} must be a list of objects.")
    return value


def _required_string(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} is missing a non-empty {key} value.")
    return value


def _error_code(payload: dict[str, Any], context: str) -> str | None:
    if "Error" not in payload:
        return None
    error = payload["Error"]
    if not isinstance(error, dict):
        raise ValueError(f"{context} Error must be an object.")
    return _required_string(error, "Code", f"{context} Error")


def _reject_unexpected_error(payload: dict[str, Any], context: str) -> None:
    error_code = _error_code(payload, context)
    if error_code is not None:
        raise ValueError(f"{context} collection failed with AWS error {error_code}.")


def _public_access_block(payload: dict[str, Any], context: str) -> dict[str, bool]:
    error_code = _error_code(payload, context)
    if error_code == NO_PUBLIC_ACCESS_BLOCK:
        return {normalized_key: False for normalized_key in PAB_FIELDS.values()}
    if error_code is not None:
        raise ValueError(f"{context} collection failed with AWS error {error_code}.")

    configuration = _required_object(payload, "PublicAccessBlockConfiguration", context)
    normalized: dict[str, bool] = {}
    for aws_key, normalized_key in PAB_FIELDS.items():
        value = configuration.get(aws_key)
        if not isinstance(value, bool):
            raise ValueError(f"{context} field {aws_key} must be a boolean.")
        normalized[normalized_key] = value
    return normalized


def _normalize_policy_statement(statement: dict[str, Any]) -> dict[str, Any]:
    key_map = {
        "Sid": "sid",
        "Effect": "effect",
        "Principal": "principal",
        "NotPrincipal": "not_principal",
        "Action": "action",
        "NotAction": "not_action",
        "Resource": "resource",
        "NotResource": "not_resource",
        "Condition": "condition",
    }
    return {key_map.get(key, key): value for key, value in statement.items()}


def _bucket_policy(payload: dict[str, Any], context: str) -> dict[str, Any]:
    error_code = _error_code(payload, context)
    if error_code == NO_BUCKET_POLICY:
        return {"statements": []}
    if error_code is not None:
        raise ValueError(f"{context} collection failed with AWS error {error_code}.")

    policy_value = payload.get("Policy")
    if isinstance(policy_value, str):
        try:
            policy_value = parse_bounded_json_text(
                policy_value,
                label=f"{context} Policy",
            )
        except json.JSONDecodeError as exc:
            raise ValueError(f"{context} Policy is not valid JSON.") from exc
    if not isinstance(policy_value, dict):
        raise ValueError(f"{context} Policy must be a JSON object or encoded JSON string.")

    statements = policy_value.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not all(
        isinstance(statement, dict) for statement in statements
    ):
        raise ValueError(f"{context} Policy Statement must be an object or list of objects.")
    return {
        "statements": [_normalize_policy_statement(statement) for statement in statements]
    }


def _grantee_name(grantee: dict[str, Any], owner_id: str, context: str) -> str:
    grantee_type = _required_string(grantee, "Type", context)
    uri = grantee.get("URI")
    canonical_id = grantee.get("ID")
    email = grantee.get("EmailAddress")
    display_name = grantee.get("DisplayName")

    if isinstance(uri, str) and uri:
        return uri
    if isinstance(canonical_id, str) and canonical_id:
        if grantee_type == "CanonicalUser" and canonical_id == owner_id:
            return "AccountOwner"
        return f"CanonicalUser:{canonical_id}"
    if isinstance(email, str) and email:
        return f"Email:{email}"
    if isinstance(display_name, str) and display_name:
        return f"DisplayName:{display_name}"
    raise ValueError(f"{context} has no URI, ID, EmailAddress, or DisplayName identifier.")


def _bucket_acl(payload: dict[str, Any], context: str) -> dict[str, Any]:
    _reject_unexpected_error(payload, context)
    owner = _required_object(payload, "Owner", context)
    owner_id = _required_string(owner, "ID", f"{context} Owner")
    grants = _required_object_list(payload, "Grants", context)
    normalized_grants: list[dict[str, str]] = []
    for index, grant in enumerate(grants):
        grant_context = f"{context} grant {index + 1}"
        grantee = _required_object(grant, "Grantee", grant_context)
        normalized_grants.append(
            {
                "grantee": _grantee_name(grantee, owner_id, f"{grant_context} Grantee"),
                "permission": _required_string(grant, "Permission", grant_context),
            }
        )
    return {"grants": normalized_grants}


def _bucket_ownership(
    payload: dict[str, Any],
    context: str,
    warnings: list[str],
) -> str:
    error_code = _error_code(payload, context)
    if error_code == NO_OWNERSHIP_CONTROLS:
        warnings.append(
            f"{context} has no explicit ownership controls; "
            "legacy ACL-enabled ObjectWriter behavior was used."
        )
        return "ObjectWriter"
    if error_code is not None:
        raise ValueError(f"{context} collection failed with AWS error {error_code}.")

    controls = _required_object(payload, "OwnershipControls", context)
    rules = _required_object_list(controls, "Rules", f"{context} OwnershipControls")
    if len(rules) != 1:
        raise ValueError(f"{context} OwnershipControls Rules must contain exactly one rule.")
    ownership = _required_string(rules[0], "ObjectOwnership", f"{context} rule")
    if ownership not in OBJECT_OWNERSHIP_VALUES:
        raise ValueError(
            f"{context} ObjectOwnership must be BucketOwnerEnforced, "
            "BucketOwnerPreferred, or ObjectWriter."
        )
    return ownership


def _validate_blocked_encryption_types(rule: dict[str, Any], context: str) -> bool:
    if "BlockedEncryptionTypes" not in rule:
        return False
    blocked = _required_object(rule, "BlockedEncryptionTypes", context)
    encryption_types = blocked.get("EncryptionType")
    if isinstance(encryption_types, str):
        values = [encryption_types]
    elif isinstance(encryption_types, list) and encryption_types and all(
        isinstance(value, str) for value in encryption_types
    ):
        values = encryption_types
    else:
        raise ValueError(
            f"{context} BlockedEncryptionTypes EncryptionType must be a string "
            "or non-empty list of strings."
        )
    if any(value not in {"SSE-C", "NONE"} for value in values):
        raise ValueError(
            f"{context} BlockedEncryptionTypes EncryptionType must contain SSE-C or NONE."
        )
    return True


def _bucket_encryption(
    payload: dict[str, Any],
    context: str,
    warnings: list[str],
) -> dict[str, Any]:
    _reject_unexpected_error(payload, context)
    configuration = _required_object(payload, "ServerSideEncryptionConfiguration", context)
    rules = _required_object_list(configuration, "Rules", f"{context} configuration")
    if not rules:
        raise ValueError(f"{context} configuration Rules must not be empty.")

    has_blocked_encryption_rule = False
    for index, rule in enumerate(rules):
        if _validate_blocked_encryption_types(rule, f"{context} rule {index + 1}"):
            has_blocked_encryption_rule = True
    default_rules = [rule for rule in rules if "ApplyServerSideEncryptionByDefault" in rule]
    if not default_rules:
        if not has_blocked_encryption_rule:
            raise ValueError(
                f"{context} contains neither a default nor blocked encryption rule."
            )
        warnings.append(
            f"{context} omitted ApplyServerSideEncryptionByDefault; "
            "the S3 SSE-S3 baseline was used."
        )
        return {"enabled": True, "algorithm": "AES256"}
    if len(default_rules) > 1:
        raise ValueError(f"{context} contains multiple default encryption rules.")

    default = _required_object(
        default_rules[0],
        "ApplyServerSideEncryptionByDefault",
        context,
    )
    normalized: dict[str, Any] = {
        "enabled": True,
        "algorithm": _required_string(default, "SSEAlgorithm", context),
    }
    key_id = default.get("KMSMasterKeyID")
    if key_id is not None:
        if not isinstance(key_id, str) or not key_id:
            raise ValueError(f"{context} KMSMasterKeyID must be a non-empty string.")
        normalized["key_id"] = key_id
    return normalized


def _bucket_versioning(payload: dict[str, Any], context: str) -> dict[str, str]:
    _reject_unexpected_error(payload, context)
    status = payload.get("Status")
    if status is None:
        return {"status": "Disabled"}
    if status not in {"Enabled", "Suspended"}:
        raise ValueError(f"{context} Status must be Enabled, Suspended, or absent.")
    return {"status": status}


def _bucket_inventory(list_buckets: dict[str, Any]) -> dict[str, str | None]:
    if list_buckets.get("Prefix"):
        raise ValueError("ListBuckets evidence is prefix-filtered; collect the full bucket inventory.")
    for pagination_key in ("ContinuationToken", "NextToken"):
        if list_buckets.get(pagination_key):
            raise ValueError(
                "ListBuckets evidence is paginated; collect all pages before analysis."
            )

    buckets = _required_object_list(list_buckets, "Buckets", "ListBuckets")
    enforce_collection_limit(
        len(buckets),
        label="AWS S3 bucket inventory",
    )
    inventory: dict[str, str | None] = {}
    seen: set[str] = set()
    for bucket in buckets:
        name = _required_string(bucket, "Name", "ListBuckets bucket")
        if name in seen:
            raise ValueError(f"ListBuckets contains duplicate bucket {name}.")
        region = bucket.get("BucketRegion")
        if region is not None and (
            not isinstance(region, str) or not region.strip()
        ):
            raise ValueError(
                f"ListBuckets bucket {name} BucketRegion must be a non-empty string."
            )
        seen.add(name)
        inventory[name] = region.lower() if isinstance(region, str) else None
    return inventory


def normalize_aws_s3_environment(evidence_bundle: dict[str, Any]) -> S3NormalizationResult:
    """Convert an AWS S3 evidence bundle into storage analyzer input."""

    validate_json_value_limits(
        evidence_bundle,
        label="AWS S3 evidence bundle",
    )
    if evidence_bundle.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            "AWS S3 evidence bundle must use schema_version "
            f"{SCHEMA_VERSION!r}."
        )
    account_id = evidence_bundle.get("account_id")
    if not isinstance(account_id, str) or not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise ValueError("AWS S3 evidence bundle account_id must be a 12-digit string.")

    list_buckets = _required_object(evidence_bundle, "ListBuckets", "S3 evidence bundle")
    bucket_inventory = _bucket_inventory(list_buckets)
    bucket_names = list(bucket_inventory)
    account_pab_payload = _required_object(
        evidence_bundle,
        "AccountPublicAccessBlock",
        "S3 evidence bundle",
    )
    account_pab = _public_access_block(
        account_pab_payload,
        "AccountPublicAccessBlock",
    )
    bucket_evidence = _required_object_list(
        evidence_bundle,
        "BucketEvidence",
        "S3 evidence bundle",
    )
    enforce_collection_limit(
        len(bucket_evidence),
        label="AWS S3 bucket evidence",
    )

    evidence_by_name: dict[str, dict[str, Any]] = {}
    for evidence in bucket_evidence:
        bucket_name = _required_string(evidence, "BucketName", "BucketEvidence entry")
        if bucket_name in evidence_by_name:
            raise ValueError(f"BucketEvidence contains duplicate bucket {bucket_name}.")
        evidence_by_name[bucket_name] = evidence

    listed = set(bucket_names)
    provided = set(evidence_by_name)
    missing = sorted(listed - provided)
    extra = sorted(provided - listed)
    if missing:
        raise ValueError("BucketEvidence is missing listed bucket(s): " + ", ".join(missing))
    if extra:
        raise ValueError("BucketEvidence contains unlisted bucket(s): " + ", ".join(extra))

    warnings: list[str] = []
    normalized_buckets: list[dict[str, Any]] = []
    for bucket_name in bucket_names:
        evidence = evidence_by_name[bucket_name]
        bucket_pab = _public_access_block(
            _required_object(evidence, "GetPublicAccessBlock", f"Bucket {bucket_name}"),
            f"Bucket {bucket_name} GetPublicAccessBlock",
        )
        effective_pab = {
            key: account_pab[key] or bucket_pab[key]
            for key in account_pab
        }
        normalized_bucket = {
            "name": bucket_name,
            "public_access_block": effective_pab,
            "object_ownership": _bucket_ownership(
                _required_object(
                    evidence,
                    "GetBucketOwnershipControls",
                    f"Bucket {bucket_name}",
                ),
                f"Bucket {bucket_name} GetBucketOwnershipControls",
                warnings,
            ),
            "acl": _bucket_acl(
                _required_object(evidence, "GetBucketAcl", f"Bucket {bucket_name}"),
                f"Bucket {bucket_name} GetBucketAcl",
            ),
            "bucket_policy": _bucket_policy(
                _required_object(evidence, "GetBucketPolicy", f"Bucket {bucket_name}"),
                f"Bucket {bucket_name} GetBucketPolicy",
            ),
            "encryption": _bucket_encryption(
                _required_object(evidence, "GetBucketEncryption", f"Bucket {bucket_name}"),
                f"Bucket {bucket_name} GetBucketEncryption",
                warnings,
            ),
            "versioning": _bucket_versioning(
                _required_object(evidence, "GetBucketVersioning", f"Bucket {bucket_name}"),
                f"Bucket {bucket_name} GetBucketVersioning",
            ),
        }
        bucket_region = bucket_inventory[bucket_name]
        if bucket_region is not None:
            normalized_bucket["region"] = bucket_region
        normalized_buckets.append(normalized_bucket)

    environment = {"account_id": account_id, "buckets": normalized_buckets}
    validate_analysis_input_limits("storage", environment)
    return S3NormalizationResult(
        environment=environment,
        warnings=tuple(warnings),
    )


def load_aws_s3_environment(path: Path) -> S3NormalizationResult:
    """Load and normalize a versioned AWS S3 evidence bundle."""

    return normalize_aws_s3_environment(_load_json_object(path))
