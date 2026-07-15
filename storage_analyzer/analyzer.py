"""Analyze offline storage configuration data for exposure risks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cloud_findings import Finding, findings_to_dicts, sort_findings, write_findings


REF_AWS_S3_BLOCK_PUBLIC_ACCESS = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
REF_AWS_S3_ACLS = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"
REF_AWS_S3_BUCKET_POLICIES = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html"
REF_AWS_S3_ENCRYPTION = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html"
REF_AWS_S3_DEFAULT_ENCRYPTION = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html"
REF_AWS_S3_VERSIONING = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
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


def _is_public_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(_is_public_principal(value) for value in principal.values())
    if isinstance(principal, list):
        return any(_is_public_principal(value) for value in principal)
    return False


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
            metadata=metadata or {},
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

    for index, grant in enumerate(bucket.get("acl", {}).get("grants", [])):
        grantee = str(grant.get("grantee", ""))
        permission = str(grant.get("permission", ""))
        if grantee in PUBLIC_GRANTEES:
            _add_finding(
                findings,
                severity="critical",
                rule_id="STO-002",
                resource_id=bucket_name,
                title="Bucket ACL grants public access",
                evidence=f"ACL grant {index + 1} gives {permission} permission to {grantee}.",
                impact="Objects or bucket metadata may be exposed to public or broadly authenticated users.",
                remediation="Remove public ACL grants and rely on private bucket ownership plus scoped IAM policies.",
                references=[REF_AWS_S3_ACLS, REF_AWS_S3_BLOCK_PUBLIC_ACCESS],
                metadata={"grantee": grantee, "permission": permission},
            )

    for index, statement in enumerate(_statements(bucket.get("bucket_policy", {}))):
        if _statement_effect(statement) != "allow":
            continue
        principal = _principal_value(statement)
        if _is_public_principal(principal):
            _add_finding(
                findings,
                severity="critical",
                rule_id="STO-003",
                resource_id=bucket_name,
                title="Bucket policy allows public principal",
                evidence=f"Allow statement grants access to public principal: {json.dumps(principal)}.",
                impact="Bucket data may be publicly accessible depending on the allowed action and resource scope.",
                remediation="Replace public principals with specific AWS principals and validate whether anonymous access is required.",
                references=[REF_AWS_S3_BUCKET_POLICIES, REF_AWS_S3_BLOCK_PUBLIC_ACCESS],
                metadata={"statement_index": str(index + 1)},
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

    return findings


def analyze_environment(environment: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in environment.get("buckets", []):
        findings.extend(analyze_bucket(bucket))
    return sort_findings(findings)


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
