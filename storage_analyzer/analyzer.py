"""Analyze offline storage configuration data for exposure risks."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cloud_findings import (
    EvidenceReference,
    Finding,
    sort_findings,
    with_findings_context,
    write_findings,
)
from cloud_rules import validate_rule_emission

REF_AWS_S3_BLOCK_PUBLIC_ACCESS = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
REF_AWS_S3_ACLS = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"
REF_AWS_S3_BUCKET_POLICIES = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html"
REF_AWS_S3_ENCRYPTION = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html"
REF_AWS_S3_DEFAULT_ENCRYPTION = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html"
REF_AWS_S3_VERSIONING = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
REF_AWS_S3_OBJECT_OWNERSHIP = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html"
REF_AWS_CONFIG_S3_ACL_PROHIBITED = "https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-acl-prohibited.html"
REF_MITRE_CLOUD_STORAGE_DISCOVERY = "https://attack.mitre.org/techniques/T1619/"

PUBLIC_ACCESS_BLOCK_KEYS = (
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
)

PUBLIC_GRANTEES = {
    "AllUsers",
    "AuthenticatedUsers",
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

FIXED_VALUE_CONDITION_KEYS = {
    "aws:principalorgid",
    "aws:sourceaccount",
    "aws:sourcearn",
    "aws:sourceowner",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:userid",
    "s3:dataaccesspointaccount",
    "s3:dataaccesspointarn",
}

FIXED_VALUE_OPERATORS = {
    "arnequals",
    "arnlike",
    "foranyvalue:arnequals",
    "foranyvalue:arnlike",
    "foranyvalue:stringequals",
    "foranyvalue:stringlike",
    "forallvalues:arnequals",
    "forallvalues:arnlike",
    "forallvalues:stringequals",
    "forallvalues:stringlike",
    "stringequals",
    "stringequalsignorecase",
    "stringlike",
}

SOURCE_IP_OPERATORS = {
    "foranyvalue:ipaddress",
    "forallvalues:ipaddress",
    "ipaddress",
}

RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

DATA_ACCESS_POINT_ARN_PATTERN = re.compile(
    r"^arn:[^:*?${}]+:s3:[^:*?${}]+:\d{12}:accesspoint/(?:\*|[^*?${}]+)$"
)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy.get("statements")
    if statements is None:
        statements = policy.get("Statement", [])
    return [statement for statement in _as_list(statements) if isinstance(statement, dict)]


def _statement_effect(statement: dict[str, Any]) -> str:
    return str(statement.get("effect", statement.get("Effect", ""))).lower()


def _principal_value(statement: dict[str, Any]) -> Any:
    return statement.get("principal", statement.get("Principal"))


def _not_principal_value(statement: dict[str, Any]) -> Any:
    return statement.get("not_principal", statement.get("NotPrincipal"))


def _condition_value(statement: dict[str, Any]) -> Any:
    return statement.get("condition", statement.get("Condition"))


def _is_public_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(_is_public_principal(value) for value in principal.values())
    if isinstance(principal, list):
        return any(_is_public_principal(value) for value in principal)
    return False


def _broad_principal_kind(statement: dict[str, Any]) -> str | None:
    if _not_principal_value(statement) is not None:
        return "NotPrincipal"
    if _is_public_principal(_principal_value(statement)):
        return "Principal"
    return None


def _condition_values(value: Any) -> list[str] | None:
    if isinstance(value, str) and value:
        return [value]
    if (
        isinstance(value, list)
        and value
        and all(isinstance(item, str) and item for item in value)
    ):
        return value
    return None


def _is_fixed_value(condition_key: str, value: str) -> bool:
    if condition_key == "s3:dataaccesspointarn":
        return DATA_ACCESS_POINT_ARN_PATTERN.fullmatch(value) is not None
    return not any(marker in value for marker in ("*", "?", "${"))


def _source_ip_is_non_public(value: str) -> bool:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False

    if isinstance(network, ipaddress.IPv4Network):
        if any(network.subnet_of(private_network) for private_network in RFC1918_NETWORKS):
            return True
        return network.prefixlen >= 8
    return network.prefixlen >= 32


def _fixed_condition_guard_keys(condition: Any) -> tuple[str, ...]:
    if not isinstance(condition, dict):
        return ()

    guard_keys: set[str] = set()
    for operator, clause in condition.items():
        if not isinstance(operator, str) or not isinstance(clause, dict):
            continue
        normalized_operator = operator.lower()
        for condition_key, raw_values in clause.items():
            if not isinstance(condition_key, str):
                continue
            values = _condition_values(raw_values)
            if values is None:
                continue
            normalized_key = condition_key.lower()
            if normalized_operator.startswith(
                "forallvalues:"
            ) and not _condition_requires_key(condition, normalized_key):
                continue
            if normalized_key == "aws:sourceip":
                if normalized_operator in SOURCE_IP_OPERATORS and all(
                    _source_ip_is_non_public(value) for value in values
                ):
                    guard_keys.add(condition_key)
            elif (
                normalized_key in FIXED_VALUE_CONDITION_KEYS
                and normalized_operator in FIXED_VALUE_OPERATORS
                and all(_is_fixed_value(normalized_key, value) for value in values)
            ):
                guard_keys.add(condition_key)
    return tuple(sorted(guard_keys, key=str.lower))


def _condition_requires_key(condition: dict[Any, Any], condition_key: str) -> bool:
    null_clause = next(
        (
            clause
            for operator, clause in condition.items()
            if isinstance(operator, str)
            and operator.lower() == "null"
            and isinstance(clause, dict)
        ),
        {},
    )
    raw_value = next(
        (
            value
            for key, value in null_clause.items()
            if isinstance(key, str) and key.lower() == condition_key
        ),
        None,
    )
    values = raw_value if isinstance(raw_value, list) else [raw_value]
    return bool(values) and all(
        value is False or (isinstance(value, str) and value.lower() == "false")
        for value in values
    )


def _condition_keys(condition: Any) -> tuple[str, ...]:
    if not isinstance(condition, dict):
        return ()
    keys = {
        key
        for clause in condition.values()
        if isinstance(clause, dict)
        for key in clause
        if isinstance(key, str)
    }
    return tuple(sorted(keys, key=str.lower))


def _statement_value(
    statement: dict[str, Any],
    normalized_key: str,
    aws_key: str,
    normalized_fallback: str,
    aws_fallback: str,
) -> Any:
    value = statement.get(normalized_key, statement.get(aws_key))
    if value is not None:
        return value
    return statement.get(normalized_fallback, statement.get(aws_fallback))


def _add_finding(
    findings: list[Finding],
    *,
    severity: str,
    rule_id: str,
    resource_id: str,
    title: str,
    evidence: str,
    impact: str,
    remediation: str,
    references: list[str],
    metadata: dict[str, str] | None = None,
) -> None:
    rule = validate_rule_emission(rule_id, "storage", severity)
    assert rule is not None
    evidence_types = {
        "STO-001": "s3-public-access-block",
        "STO-002": "s3-bucket-acl",
        "STO-003": "s3-bucket-policy-statement",
        "STO-004": "s3-bucket-encryption",
        "STO-005": "s3-bucket-versioning",
        "STO-006": "s3-object-ownership",
    }
    evidence_id = resource_id
    metadata_values = metadata or {}
    for key in ("statement_sid", "statement_index", "grantee"):
        value = metadata_values.get(key)
        if value:
            evidence_id += f":{key}={value}"
    findings.append(
        Finding(
            rule_id=rule_id,
            severity=severity,
            module="storage",
            category="data-exposure",
            resource_type="bucket",
            resource_id=resource_id,
            title=title,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            references=references,
            metadata=metadata_values,
            confidence=rule.confidence,
            evidence_references=[
                EvidenceReference(
                    type=evidence_types[rule_id],
                    id=evidence_id,
                )
            ],
        )
    )


def analyze_bucket(bucket: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    bucket_name = str(bucket.get("name", "unknown-bucket"))

    public_access_block = bucket.get("public_access_block", {})
    disabled_controls = [
        key for key in PUBLIC_ACCESS_BLOCK_KEYS if public_access_block.get(key) is not True
    ]
    if disabled_controls:
        _add_finding(
            findings,
            severity="high",
            rule_id="STO-001",
            resource_id=bucket_name,
            title="S3 public access block is incomplete",
            evidence=f"Disabled or missing public access block controls: {disabled_controls}.",
            impact="The bucket has weaker guardrails against public ACLs or public bucket policies.",
            remediation="Enable all four S3 Block Public Access settings unless a documented exception is required.",
            references=[REF_AWS_S3_BLOCK_PUBLIC_ACCESS, REF_MITRE_CLOUD_STORAGE_DISCOVERY],
            metadata={"disabled_controls": ", ".join(disabled_controls)},
        )

    object_ownership_value = bucket.get("object_ownership")
    object_ownership = (
        str(object_ownership_value) if object_ownership_value is not None else None
    )
    acls_disabled = object_ownership == "BucketOwnerEnforced"
    ignore_public_acls = public_access_block.get("ignore_public_acls") is True
    for index, grant in enumerate(bucket.get("acl", {}).get("grants", [])):
        grantee = str(grant.get("grantee", ""))
        permission = str(grant.get("permission", ""))
        if grantee in PUBLIC_GRANTEES and not ignore_public_acls and not acls_disabled:
            ownership_context = (
                f" Object Ownership is {object_ownership}."
                if object_ownership is not None
                else ""
            )
            _add_finding(
                findings,
                severity="critical",
                rule_id="STO-002",
                resource_id=bucket_name,
                title="Bucket ACL grants public access",
                evidence=(
                    f"ACL grant {index + 1} gives {permission} permission to {grantee}."
                    f"{ownership_context}"
                ),
                impact="Objects or bucket metadata may be exposed to public or broadly authenticated users.",
                remediation="Remove public ACL grants and rely on private bucket ownership plus scoped IAM policies.",
                references=[
                    REF_AWS_S3_ACLS,
                    REF_AWS_S3_BLOCK_PUBLIC_ACCESS,
                    REF_AWS_S3_OBJECT_OWNERSHIP,
                ],
                metadata={
                    "grantee": grantee,
                    "permission": permission,
                    "object_ownership": object_ownership or "not-provided",
                },
            )

    restrict_public_buckets = public_access_block.get("restrict_public_buckets") is True
    for index, statement in enumerate(_statements(bucket.get("bucket_policy", {}))):
        if _statement_effect(statement) != "allow":
            continue
        principal_kind = _broad_principal_kind(statement)
        if principal_kind is None or restrict_public_buckets:
            continue
        condition = _condition_value(statement)
        fixed_guard_keys = _fixed_condition_guard_keys(condition)
        if fixed_guard_keys:
            continue

        principal = (
            _not_principal_value(statement)
            if principal_kind == "NotPrincipal"
            else _principal_value(statement)
        )
        condition_keys = _condition_keys(condition)
        condition_context = (
            " Condition "
            f"{json.dumps(condition, sort_keys=True)} does not establish an "
            "AWS-recognized fixed-value guardrail."
            if condition_keys
            else " No AWS-recognized fixed-value condition guardrail is present."
        )
        action = _statement_value(
            statement,
            "action",
            "Action",
            "not_action",
            "NotAction",
        )
        resource = _statement_value(
            statement,
            "resource",
            "Resource",
            "not_resource",
            "NotResource",
        )
        statement_sid = statement.get("sid", statement.get("Sid"))
        metadata = {
            "statement_index": str(index + 1),
            "principal_element": principal_kind,
            "condition_keys": ", ".join(condition_keys),
            "block_public_policy": str(
                public_access_block.get("block_public_policy") is True
            ).lower(),
            "restrict_public_buckets": str(restrict_public_buckets).lower(),
        }
        if isinstance(statement_sid, str) and statement_sid:
            metadata["statement_sid"] = statement_sid
        _add_finding(
            findings,
            severity="critical",
            rule_id="STO-003",
            resource_id=bucket_name,
            title="Bucket policy allows an effectively public principal",
            evidence=(
                f"Allow statement uses {principal_kind} "
                f"{json.dumps(principal, sort_keys=True)} with action "
                f"{json.dumps(action, sort_keys=True)} and resource "
                f"{json.dumps(resource, sort_keys=True)}.{condition_context}"
            ),
            impact=(
                "Bucket data may be publicly accessible because the statement is public "
                "under S3 Block Public Access policy-evaluation rules."
            ),
            remediation=(
                "Replace the broad principal with specific AWS principals or add a supported "
                "fixed-value condition, then validate the result with IAM Access Analyzer for S3."
            ),
            references=[REF_AWS_S3_BUCKET_POLICIES, REF_AWS_S3_BLOCK_PUBLIC_ACCESS],
            metadata=metadata,
        )

    encryption = bucket.get("encryption", {})
    if encryption.get("enabled") is not True:
        _add_finding(
            findings,
            severity="low",
            rule_id="STO-004",
            resource_id=bucket_name,
            title="Bucket lacks an explicit encryption configuration",
            evidence="No explicit bucket-level default encryption configuration is present in the input.",
            impact=(
                "S3 applies baseline SSE-S3 encryption to new objects, but explicit key-management "
                "requirements cannot be confirmed."
            ),
            remediation=(
                "For sensitive or regulated data, configure explicit default encryption with an "
                "approved KMS key and document key ownership requirements."
            ),
            references=[REF_AWS_S3_DEFAULT_ENCRYPTION, REF_AWS_S3_ENCRYPTION],
        )

    versioning_status = str(bucket.get("versioning", {}).get("status", "Disabled"))
    if versioning_status.lower() != "enabled":
        _add_finding(
            findings,
            severity="medium",
            rule_id="STO-005",
            resource_id=bucket_name,
            title="Bucket versioning is not enabled",
            evidence=f"Bucket versioning status is {versioning_status}.",
            impact="Accidental deletion, overwrite, or destructive activity may be harder to recover from.",
            remediation="Enable bucket versioning for important data and pair it with lifecycle rules if storage cost matters.",
            references=[REF_AWS_S3_VERSIONING],
            metadata={"versioning_status": versioning_status},
        )

    if object_ownership in {"BucketOwnerPreferred", "ObjectWriter"}:
        _add_finding(
            findings,
            severity="medium",
            rule_id="STO-006",
            resource_id=bucket_name,
            title="Bucket access control lists remain enabled",
            evidence=(
                f"S3 Object Ownership is {object_ownership}, so bucket and object ACLs "
                "can still affect access."
            ),
            impact=(
                "ACL-based permissions and cross-account object ownership can make access "
                "harder to reason about and can preserve unintended grants."
            ),
            remediation=(
                "Migrate required ACL permissions to policies, reset the bucket ACL to private, "
                "and use BucketOwnerEnforced unless an ACL-dependent workload is documented."
            ),
            references=[
                REF_AWS_S3_OBJECT_OWNERSHIP,
                REF_AWS_CONFIG_S3_ACL_PROHIBITED,
            ],
            metadata={"object_ownership": object_ownership},
        )

    return with_findings_context(
        findings,
        region=str(bucket.get("region") or "unknown"),
    )


def analyze_environment(environment: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in environment.get("buckets", []):
        findings.extend(analyze_bucket(bucket))
    return sort_findings(
        with_findings_context(
            findings,
            account_id=str(environment.get("account_id") or "unknown"),
            region=str(environment.get("region") or "unknown"),
        )
    )


def load_environment(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Storage environment file must contain a JSON object.")
    return data


def print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("No storage findings detected.")
        return

    print(f"Storage findings detected: {len(findings)}")
    print()
    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.rule_id} {finding.resource_type}/{finding.resource_id}")
        print(f"Title: {finding.title}")
        print(f"Evidence: {finding.evidence}")
        print(f"Impact: {finding.impact}")
        print(f"Remediation: {finding.remediation}")
        print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze offline storage configuration JSON data for exposure risks."
    )
    parser.add_argument("input", type=Path, help="Path to the sample storage environment JSON file.")
    parser.add_argument("--output", type=Path, help="Optional path for JSON findings export.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        environment = load_environment(args.input)
        findings = analyze_environment(environment)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    print_findings(findings)

    if args.output:
        write_findings(args.output, findings)
        print(f"Findings saved to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
