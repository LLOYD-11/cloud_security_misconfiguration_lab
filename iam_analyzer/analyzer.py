"""Analyze offline IAM-style JSON data for risky cloud identity patterns."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cloud_findings import Finding, findings_to_dicts, sort_findings, write_findings


SENSITIVE_ACTION_PREFIXES = (
    "iam:",
    "sts:",
    "organizations:",
    "account:",
    "kms:",
)

S3_WRITE_ACTIONS = {
    "s3:*",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:PutBucketPolicy",
    "s3:PutBucketAcl",
    "s3:PutObjectAcl",
}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _string_values(value: Any) -> list[str]:
    return [str(item) for item in _as_list(value)]


def _statement_id(statement: dict[str, Any], index: int) -> str:
    return str(statement.get("sid") or statement.get("Sid") or f"statement-{index + 1}")


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy.get("statements")
    if statements is None:
        document = policy.get("document", {})
        statements = document.get("Statement", [])
    return [stmt for stmt in _as_list(statements) if isinstance(stmt, dict)]


def _statement_actions(statement: dict[str, Any]) -> list[str]:
    return _string_values(statement.get("action", statement.get("Action")))


def _statement_resources(statement: dict[str, Any]) -> list[str]:
    return _string_values(statement.get("resource", statement.get("Resource")))


def _statement_effect(statement: dict[str, Any]) -> str:
    return str(statement.get("effect", statement.get("Effect", ""))).lower()


def _has_mfa_condition(statement: dict[str, Any]) -> bool:
    condition = statement.get("condition", statement.get("Condition", {}))
    if not isinstance(condition, dict):
        return False
    condition_text = json.dumps(condition).lower()
    return "aws:multifactorauthpresent" in condition_text and "true" in condition_text


def _contains_wildcard(values: Iterable[str]) -> bool:
    return any("*" in value for value in values)


def _has_sensitive_action(actions: Iterable[str]) -> bool:
    for action in actions:
        if action == "*":
            return True
        if any(action.startswith(prefix) for prefix in SENSITIVE_ACTION_PREFIXES):
            return True
    return False


def _has_broad_s3_write(actions: Iterable[str]) -> bool:
    return any(action in S3_WRITE_ACTIONS for action in actions)


def _add_finding(
    findings: list[Finding],
    *,
    severity: str,
    rule_id: str,
    resource_type: str,
    resource_id: str,
    title: str,
    evidence: str,
    impact: str,
    remediation: str,
    policy_name: str = "",
    statement_id: str = "",
) -> None:
    metadata = {}
    if policy_name:
        metadata["policy_name"] = policy_name
    if statement_id:
        metadata["statement_id"] = statement_id

    findings.append(
        Finding(
            rule_id=rule_id,
            severity=severity,
            module="iam",
            category="identity-and-access",
            resource_type=resource_type,
            resource_id=resource_id,
            title=title,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            metadata=metadata,
        )
    )


def analyze_principal(
    subject_type: str,
    principal: dict[str, Any],
    account_id: str,
) -> list[Finding]:
    findings: list[Finding] = []
    subject_name = str(principal.get("name", "unknown"))

    for policy in principal.get("attached_policies", []):
        policy_name = str(policy.get("policy_name", "inline-policy"))
        for index, statement in enumerate(_statements(policy)):
            if _statement_effect(statement) != "allow":
                continue

            statement_id = _statement_id(statement, index)
            actions = _statement_actions(statement)
            resources = _statement_resources(statement)

            if "*" in actions and "*" in resources:
                _add_finding(
                    findings,
                    severity="critical",
                    rule_id="IAM-001",
                    resource_type=subject_type,
                    resource_id=subject_name,
                    title="Administrator-style wildcard permission",
                    evidence='Allow statement grants Action "*" on Resource "*".',
                    impact="The principal may have full administrative access across the account.",
                    remediation="Replace wildcard administrator access with task-specific actions and scoped resources.",
                    policy_name=policy_name,
                    statement_id=statement_id,
                )
            elif "*" in actions:
                _add_finding(
                    findings,
                    severity="high",
                    rule_id="IAM-002",
                    resource_type=subject_type,
                    resource_id=subject_name,
                    title="Wildcard action allowed",
                    evidence='Allow statement grants Action "*".',
                    impact="The principal can perform all actions against the listed resources.",
                    remediation="Limit allowed actions to the minimum service actions required.",
                    policy_name=policy_name,
                    statement_id=statement_id,
                )

            if "*" in resources:
                _add_finding(
                    findings,
                    severity="medium",
                    rule_id="IAM-003",
                    resource_type=subject_type,
                    resource_id=subject_name,
                    title="Wildcard resource scope",
                    evidence='Allow statement uses Resource "*".',
                    impact="The permission is not limited to specific cloud resources.",
                    remediation="Scope the statement to specific ARNs wherever the service supports resource-level permissions.",
                    policy_name=policy_name,
                    statement_id=statement_id,
                )

            if _has_broad_s3_write(actions) and _contains_wildcard(resources):
                _add_finding(
                    findings,
                    severity="high",
                    rule_id="IAM-004",
                    resource_type=subject_type,
                    resource_id=subject_name,
                    title="Broad S3 write permission",
                    evidence=f"S3 write action with broad resource scope: {actions} on {resources}.",
                    impact="The principal may alter or delete data across a broad set of storage resources.",
                    remediation="Restrict S3 write actions to the exact bucket and prefix required for the workload.",
                    policy_name=policy_name,
                    statement_id=statement_id,
                )

            if _has_sensitive_action(actions) and not _has_mfa_condition(statement):
                _add_finding(
                    findings,
                    severity="medium",
                    rule_id="IAM-005",
                    resource_type=subject_type,
                    resource_id=subject_name,
                    title="Sensitive action without MFA condition",
                    evidence="Sensitive action is allowed without an MFA condition.",
                    impact="Compromised credentials could be used for privileged activity without an additional identity check.",
                    remediation="Add an MFA condition for sensitive IAM, STS, KMS, account, or organization actions where appropriate.",
                    policy_name=policy_name,
                    statement_id=statement_id,
                )

    if subject_type == "user" and not principal.get("mfa_enabled", False):
        _add_finding(
            findings,
            severity="medium",
            rule_id="IAM-006",
            resource_type=subject_type,
            resource_id=subject_name,
            title="User MFA is disabled",
            evidence="User metadata shows MFA is not enabled.",
            impact="A password or access-key compromise has less resistance without multi-factor authentication.",
            remediation="Enable MFA for interactive users and prefer short-lived role credentials for automation.",
            policy_name="user-metadata",
            statement_id="mfa",
        )

    for key in principal.get("access_keys", []):
        age_days = int(key.get("age_days", 0))
        if age_days > 90:
            _add_finding(
                findings,
                severity="medium",
                rule_id="IAM-007",
                resource_type=subject_type,
                resource_id=subject_name,
                title="Long-lived access key",
                evidence=f"Access key age is {age_days} days.",
                impact="Long-lived access keys increase the window of exposure if credentials are leaked.",
                remediation="Rotate old access keys and prefer temporary credentials where possible.",
                policy_name="access-key-metadata",
                statement_id=str(key.get("id", "access-key")),
            )

    if subject_type == "role":
        findings.extend(analyze_trust_policy(principal, account_id))

    return findings


def analyze_trust_policy(role: dict[str, Any], account_id: str) -> list[Finding]:
    findings: list[Finding] = []
    role_name = str(role.get("name", "unknown-role"))
    trust_policy = role.get("trust_policy", {})

    for index, statement in enumerate(_statements(trust_policy)):
        if _statement_effect(statement) != "allow":
            continue

        principal = statement.get("principal", statement.get("Principal", {}))
        principal_text = json.dumps(principal)
        statement_id = _statement_id(statement, index)

        if account_id not in principal_text:
            _add_finding(
                findings,
                severity="high",
                rule_id="IAM-008",
                resource_type="role",
                resource_id=role_name,
                title="Cross-account role trust",
                evidence=f"Trust policy allows an external principal: {principal_text}.",
                impact="An external account or principal may be able to assume this role.",
                remediation="Require an external ID, restrict the trusted principal, and confirm the business need for cross-account access.",
                policy_name="trust-policy",
                statement_id=statement_id,
            )

    return findings


def analyze_environment(environment: dict[str, Any]) -> list[Finding]:
    account_id = str(environment.get("account_id", ""))
    findings: list[Finding] = []

    for user in environment.get("users", []):
        findings.extend(analyze_principal("user", user, account_id))

    for role in environment.get("roles", []):
        findings.extend(analyze_principal("role", role, account_id))

    return sort_findings(findings)


def load_environment(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("IAM environment file must contain a JSON object.")
    return data


def print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("No IAM findings detected.")
        return

    print(f"IAM findings detected: {len(findings)}")
    print()
    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.rule_id} {finding.resource_type}/{finding.resource_id}")
        print(f"Title: {finding.title}")
        if finding.metadata:
            policy_name = finding.metadata.get("policy_name", "n/a")
            statement_id = finding.metadata.get("statement_id", "n/a")
            print(f"Policy: {policy_name} | Statement: {statement_id}")
        print(f"Evidence: {finding.evidence}")
        print(f"Impact: {finding.impact}")
        print(f"Remediation: {finding.remediation}")
        print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze offline IAM-style JSON data for common cloud identity risks."
    )
    parser.add_argument("input", type=Path, help="Path to the sample IAM environment JSON file.")
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
