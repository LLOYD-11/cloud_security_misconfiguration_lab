"""Analyze offline IAM-style JSON data for risky cloud identity patterns."""

from __future__ import annotations

import argparse
import json
import re
import sys
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cloud_findings import Finding, sort_findings, write_findings

SENSITIVE_ACTIONS = (
    "iam:attachrolepolicy",
    "iam:attachuserpolicy",
    "iam:createaccesskey",
    "iam:createpolicyversion",
    "iam:createuser",
    "iam:deleteuser",
    "iam:passrole",
    "iam:putrolepolicy",
    "iam:putuserpolicy",
    "iam:updateassumerolepolicy",
    "organizations:leaveorganization",
    "organizations:moveaccount",
    "sts:assumerole",
    "kms:creategrant",
    "kms:disablekey",
    "kms:putkeypolicy",
    "kms:schedulekeydeletion",
)

ROLE_ASSUMPTION_ACTIONS = (
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
)

S3_WRITE_ACTIONS = (
    "s3:putobject",
    "s3:deleteobject",
    "s3:putbucketpolicy",
    "s3:putbucketacl",
    "s3:putobjectacl",
)

STALE_CREDENTIAL_DAYS = 90
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
IAM_ARN_ACCOUNT_PATTERN = re.compile(r"^arn:[^:]+:iam::(\d{12}):")

REF_MITRE_CLOUD_ACCOUNTS = "https://attack.mitre.org/techniques/T1078/004/"
REF_MITRE_TRUSTED_RELATIONSHIP = "https://attack.mitre.org/techniques/T1199/"
REF_AWS_IAM_BEST_PRACTICES = "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
REF_AWS_CREDENTIAL_REPORT = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html"
)
REF_AWS_PERMISSIONS_BOUNDARIES = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html"
)
REF_AWS_POLICY_CHECKS = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html"
)
REF_AWS_PRINCIPAL_ELEMENT = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"
)
REF_AWS_ROLE_EXTERNAL_ID = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html"
)

TRUST_GUARDRAIL_KEYS = {
    "aws:principalarn": "aws:PrincipalArn",
    "aws:principalorgid": "aws:PrincipalOrgID",
    "sts:externalid": "sts:ExternalId",
}
TRUST_GUARDRAIL_OPERATORS = {
    "aws:principalarn": {"arnequals", "stringequals"},
    "aws:principalorgid": {"stringequals"},
    "sts:externalid": {"stringequals"},
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


def _statement_not_actions(statement: dict[str, Any]) -> list[str]:
    return _string_values(statement.get("not_action", statement.get("NotAction")))


def _statement_resources(statement: dict[str, Any]) -> list[str]:
    return _string_values(statement.get("resource", statement.get("Resource")))


def _statement_not_resources(statement: dict[str, Any]) -> list[str]:
    return _string_values(statement.get("not_resource", statement.get("NotResource")))


def _statement_effect(statement: dict[str, Any]) -> str:
    return str(statement.get("effect", statement.get("Effect", ""))).lower()


def _has_mfa_condition(statement: dict[str, Any]) -> bool:
    condition = statement.get("condition", statement.get("Condition", {}))
    if not isinstance(condition, dict):
        return False

    for operator_values in condition.values():
        if not isinstance(operator_values, dict):
            continue
        for key, value in operator_values.items():
            if str(key).lower() != "aws:multifactorauthpresent":
                continue
            return any(str(item).lower() == "true" for item in _as_list(value))
    return False


def _contains_wildcard(values: Iterable[str]) -> bool:
    return any("*" in value or "?" in value for value in values)


def _wildcard_values(values: Iterable[str]) -> list[str]:
    return [value for value in values if "*" in value or "?" in value]


def _trust_guardrails(statement: dict[str, Any]) -> list[str]:
    condition = statement.get("condition", statement.get("Condition", {}))
    if not isinstance(condition, dict):
        return []

    guardrails: set[str] = set()
    for operator, operator_values in condition.items():
        normalized_operator = str(operator).lower()
        if not isinstance(operator_values, dict):
            continue
        for key, value in operator_values.items():
            normalized_key = str(key).lower()
            if normalized_operator not in TRUST_GUARDRAIL_OPERATORS.get(
                normalized_key, set()
            ):
                continue
            values = _as_list(value)
            if values and all(
                isinstance(item, str)
                and item
                and not _contains_wildcard([item])
                for item in values
            ):
                guardrails.add(TRUST_GUARDRAIL_KEYS[normalized_key])
    return sorted(guardrails)


def _has_sensitive_action(actions: Iterable[str]) -> bool:
    for action in actions:
        normalized = action.lower()
        if normalized == "*":
            return True
        if any(fnmatchcase(sensitive_action, normalized) for sensitive_action in SENSITIVE_ACTIONS):
            return True
    return False


def _allows_role_assumption(statement: dict[str, Any]) -> bool:
    actions = [action.lower() for action in _statement_actions(statement)]
    if actions:
        return any(
            fnmatchcase(assume_action, allowed_pattern)
            for allowed_pattern in actions
            for assume_action in ROLE_ASSUMPTION_ACTIONS
        )

    excluded_actions = [
        action.lower() for action in _statement_not_actions(statement)
    ]
    if excluded_actions:
        return any(
            not any(
                fnmatchcase(assume_action, excluded_pattern)
                for excluded_pattern in excluded_actions
            )
            for assume_action in ROLE_ASSUMPTION_ACTIONS
        )
    return False


def _has_broad_s3_write(actions: Iterable[str]) -> bool:
    for action in actions:
        normalized = action.lower()
        if not normalized.startswith("s3:"):
            continue
        if any(fnmatchcase(write_action, normalized) for write_action in S3_WRITE_ACTIONS):
            return True
    return False


def _principal_strings(value: Any) -> list[str]:
    values: list[str] = []
    for item in _as_list(value):
        if isinstance(item, list):
            values.extend(_principal_strings(item))
        else:
            values.append(str(item))
    return values


def _principal_account_id(principal: str) -> str | None:
    if ACCOUNT_ID_PATTERN.fullmatch(principal):
        return principal
    match = IAM_ARN_ACCOUNT_PATTERN.match(principal)
    return match.group(1) if match else None


def _external_principals(principal: Any, account_id: str) -> list[str]:
    if principal == "*":
        return ["*"]
    if not isinstance(principal, dict) or not account_id:
        return []

    candidates: list[str] = []
    for principal_type in ("AWS", "Federated"):
        candidates.extend(_principal_strings(principal.get(principal_type)))

    external: list[str] = []
    for candidate in candidates:
        if candidate == "*":
            external.append(candidate)
            continue
        principal_account = _principal_account_id(candidate)
        if principal_account and principal_account != account_id:
            external.append(candidate)
    return external


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
    references: list[str] | None = None,
    policy_name: str = "",
    statement_id: str = "",
    extra_metadata: dict[str, str] | None = None,
) -> None:
    metadata = dict(extra_metadata or {})
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
            references=references or [],
            metadata=metadata,
        )
    )


def _policy_metadata(
    principal: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, str]:
    metadata: dict[str, str] = {}
    policy_source = policy.get("policy_source")
    if policy_source:
        metadata["policy_source"] = str(policy_source)
    policy_arn = policy.get("policy_arn")
    if policy_arn:
        metadata["policy_arn"] = str(policy_arn)

    members = principal.get("members")
    if isinstance(members, list):
        metadata["member_count"] = str(len(members))
        if members:
            metadata["members"] = ", ".join(str(member) for member in members)

    boundary = principal.get("permissions_boundary")
    if isinstance(boundary, dict):
        boundary_arn = boundary.get("policy_arn")
        if boundary_arn:
            metadata["permissions_boundary"] = str(boundary_arn)
        metadata["boundary_document"] = (
            "available" if boundary.get("document_available") is True else "unavailable"
        )
    return metadata


def analyze_permissions_boundary(
    subject_type: str,
    principal: dict[str, Any],
) -> list[Finding]:
    boundary = principal.get("permissions_boundary")
    if not isinstance(boundary, dict) or boundary.get("document_available") is not True:
        return []

    findings: list[Finding] = []
    subject_name = str(principal.get("name", "unknown"))
    policy_name = str(boundary.get("policy_name", "permissions-boundary"))
    boundary_arn = str(boundary.get("policy_arn", policy_name))
    for index, statement in enumerate(_statements(boundary)):
        if _statement_effect(statement) != "allow":
            continue
        actions = _statement_actions(statement)
        resources = _statement_resources(statement)
        if "*" not in actions or "*" not in resources:
            continue
        _add_finding(
            findings,
            severity="medium",
            rule_id="IAM-015",
            resource_type=subject_type,
            resource_id=subject_name,
            title="Permissions boundary does not constrain access",
            evidence='The permissions boundary allows Action "*" on Resource "*".',
            impact=(
                "The boundary does not reduce the maximum permissions that identity policies "
                "can grant to this principal."
            ),
            remediation=(
                "Replace the unrestricted boundary with an explicit maximum-permissions policy "
                "that matches the principal's delegated responsibilities."
            ),
            references=[REF_AWS_PERMISSIONS_BOUNDARIES, REF_AWS_IAM_BEST_PRACTICES],
            policy_name=policy_name,
            statement_id=_statement_id(statement, index),
            extra_metadata={
                "permissions_boundary": boundary_arn,
                "boundary_document": "available",
            },
        )
    return findings


def analyze_root_account(root_account: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    if root_account.get("password_enabled") is True and not root_account.get(
        "mfa_enabled", False
    ):
        _add_finding(
            findings,
            severity="critical",
            rule_id="IAM-014",
            resource_type="root-account",
            resource_id="root",
            title="Root account MFA is disabled",
            evidence="Credential-report evidence shows an active root password without MFA.",
            impact="A compromised root password could provide unrestricted account control.",
            remediation=(
                "Enable MFA for the root user, avoid routine root use, and store recovery "
                "credentials securely."
            ),
            references=[REF_AWS_IAM_BEST_PRACTICES, REF_AWS_CREDENTIAL_REPORT],
            policy_name="credential-report",
            statement_id="root-mfa",
        )

    for key in root_account.get("access_keys", []):
        if str(key.get("status", "Active")).lower() == "inactive":
            continue
        _add_finding(
            findings,
            severity="critical",
            rule_id="IAM-013",
            resource_type="root-account",
            resource_id="root",
            title="Root account has an active access key",
            evidence=(
                f"Credential-report slot {key.get('id', 'access-key')} is active "
                f"and {int(key.get('age_days', 0))} days old."
            ),
            impact="Root access keys provide long-lived unrestricted programmatic account access.",
            remediation=(
                "Delete root access keys and use least-privilege IAM roles with temporary "
                "credentials for programmatic access."
            ),
            references=[REF_AWS_IAM_BEST_PRACTICES, REF_AWS_CREDENTIAL_REPORT],
            policy_name="credential-report",
            statement_id=str(key.get("id", "root-access-key")),
        )

    return findings


def analyze_principal(
    subject_type: str,
    principal: dict[str, Any],
    account_id: str,
) -> list[Finding]:
    findings: list[Finding] = []
    subject_name = str(principal.get("name", "unknown"))

    for policy in principal.get("attached_policies", []):
        policy_name = str(policy.get("policy_name", "inline-policy"))
        policy_metadata = _policy_metadata(principal, policy)
        for index, statement in enumerate(_statements(policy)):
            if _statement_effect(statement) != "allow":
                continue

            statement_id = _statement_id(statement, index)
            actions = _statement_actions(statement)
            not_actions = _statement_not_actions(statement)
            resources = _statement_resources(statement)
            not_resources = _statement_not_resources(statement)
            wildcard_actions = _wildcard_values(actions)

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
                    references=[REF_MITRE_CLOUD_ACCOUNTS, REF_AWS_IAM_BEST_PRACTICES],
                    policy_name=policy_name,
                    statement_id=statement_id,
                    extra_metadata=policy_metadata,
                )
            elif wildcard_actions:
                broad_wildcard = any(
                    action == "*" or action.endswith(":*") for action in wildcard_actions
                )
                _add_finding(
                    findings,
                    severity="high" if broad_wildcard else "medium",
                    rule_id="IAM-002",
                    resource_type=subject_type,
                    resource_id=subject_name,
                    title="Wildcard action allowed",
                    evidence=f"Allow statement uses wildcard action pattern(s): {wildcard_actions}.",
                    impact=(
                        "The policy can automatically include multiple current or future API "
                        "operations that match the wildcard."
                    ),
                    remediation=(
                        "Replace wildcard action patterns with the minimum explicit API actions "
                        "required by the workload."
                    ),
                    references=[REF_MITRE_CLOUD_ACCOUNTS, REF_AWS_IAM_BEST_PRACTICES],
                    policy_name=policy_name,
                    statement_id=statement_id,
                    extra_metadata=policy_metadata,
                )

            if actions and "*" in resources:
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
                    references=[REF_MITRE_CLOUD_ACCOUNTS, REF_AWS_IAM_BEST_PRACTICES],
                    policy_name=policy_name,
                    statement_id=statement_id,
                    extra_metadata=policy_metadata,
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
                    references=[REF_AWS_IAM_BEST_PRACTICES],
                    policy_name=policy_name,
                    statement_id=statement_id,
                    extra_metadata=policy_metadata,
                )

            if (
                subject_type in {"user", "group"}
                and _has_sensitive_action(actions)
                and not _has_mfa_condition(statement)
            ):
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
                    references=[REF_AWS_IAM_BEST_PRACTICES],
                    policy_name=policy_name,
                    statement_id=statement_id,
                    extra_metadata=policy_metadata,
                )

            if not_actions:
                _add_finding(
                    findings,
                    severity="high" if "*" in resources else "medium",
                    rule_id="IAM-009",
                    resource_type=subject_type,
                    resource_id=subject_name,
                    title="Broad allow uses NotAction",
                    evidence=(
                        f"Allow statement excludes only NotAction {not_actions} "
                        f"for resources {resources or not_resources}."
                    ),
                    impact=(
                        "NotAction in an Allow statement can grant every applicable action except "
                        "the exclusions, including services added later."
                    ),
                    remediation=(
                        "Replace the broad complement with an explicit Action allowlist and "
                        "scope resources wherever supported."
                    ),
                    references=[REF_AWS_POLICY_CHECKS, REF_AWS_IAM_BEST_PRACTICES],
                    policy_name=policy_name,
                    statement_id=statement_id,
                    extra_metadata=policy_metadata,
                )

            if not_resources:
                _add_finding(
                    findings,
                    severity=(
                        "high"
                        if _has_sensitive_action(actions) or _contains_wildcard(actions)
                        else "medium"
                    ),
                    rule_id="IAM-010",
                    resource_type=subject_type,
                    resource_id=subject_name,
                    title="Broad allow uses NotResource",
                    evidence=(
                        f"Allow statement grants actions {actions or not_actions} to every "
                        f"applicable resource except {not_resources}."
                    ),
                    impact=(
                        "New or unintended resources outside the exclusion list can inherit "
                        "the allowed actions."
                    ),
                    remediation=(
                        "Replace NotResource with an explicit Resource allowlist for the intended "
                        "resources."
                    ),
                    references=[REF_AWS_POLICY_CHECKS, REF_AWS_IAM_BEST_PRACTICES],
                    policy_name=policy_name,
                    statement_id=statement_id,
                    extra_metadata=policy_metadata,
                )

    password_enabled = principal.get("password_enabled", True)
    if (
        subject_type == "user"
        and password_enabled is not False
        and not principal.get("mfa_enabled", False)
    ):
        evidence = "User has an active console password without MFA."
        if "password_enabled" not in principal:
            evidence = (
                "User metadata does not show MFA; console-password status was not supplied "
                "and is treated as enabled for backward compatibility."
            )
        _add_finding(
            findings,
            severity="medium",
            rule_id="IAM-006",
            resource_type=subject_type,
            resource_id=subject_name,
            title="User MFA is disabled",
            evidence=evidence,
            impact="A compromised console password has less resistance without MFA.",
            remediation="Enable MFA for interactive IAM users or remove console access.",
            references=[REF_AWS_IAM_BEST_PRACTICES, REF_AWS_CREDENTIAL_REPORT],
            policy_name="credential-report",
            statement_id="mfa",
        )

    if subject_type == "user":
        for key in principal.get("access_keys", []):
            if str(key.get("status", "Active")).lower() == "inactive":
                continue
            age_days = int(key.get("age_days", 0))
            key_id = str(key.get("id", "access-key"))
            if age_days > STALE_CREDENTIAL_DAYS:
                _add_finding(
                    findings,
                    severity="medium",
                    rule_id="IAM-007",
                    resource_type=subject_type,
                    resource_id=subject_name,
                    title="Long-lived access key",
                    evidence=f"Active access key age is {age_days} days.",
                    impact=(
                        "Long-lived access keys increase the window of exposure if credentials "
                        "are leaked."
                    ),
                    remediation=(
                        "Rotate old access keys and prefer temporary role credentials where "
                        "possible."
                    ),
                    references=[REF_AWS_IAM_BEST_PRACTICES, REF_AWS_CREDENTIAL_REPORT],
                    policy_name="credential-report",
                    statement_id=key_id,
                )

            if "last_used_days" not in key:
                continue
            last_used_days = key.get("last_used_days")
            is_stale = (
                last_used_days is None and age_days > STALE_CREDENTIAL_DAYS
            ) or (
                isinstance(last_used_days, int)
                and not isinstance(last_used_days, bool)
                and last_used_days > STALE_CREDENTIAL_DAYS
            )
            if is_stale:
                usage_evidence = (
                    f"has never been used and is {age_days} days old"
                    if last_used_days is None
                    else f"was last used {last_used_days} days ago"
                )
                _add_finding(
                    findings,
                    severity="medium",
                    rule_id="IAM-011",
                    resource_type=subject_type,
                    resource_id=subject_name,
                    title="Stale active access key",
                    evidence=f"Active access key {key_id} {usage_evidence}.",
                    impact=(
                        "Unused active credentials can remain unnoticed and available to an "
                        "attacker."
                    ),
                    remediation=(
                        "Confirm the key is no longer required, disable it, monitor for impact, "
                        "and then delete it."
                    ),
                    references=[REF_AWS_IAM_BEST_PRACTICES, REF_AWS_CREDENTIAL_REPORT],
                    policy_name="credential-report",
                    statement_id=key_id,
                )

        if password_enabled is True and "password_last_used_days" in principal:
            password_last_used_days = principal.get("password_last_used_days")
            password_age_days = principal.get("password_age_days")
            password_is_stale = (
                password_last_used_days is None
                and isinstance(password_age_days, int)
                and not isinstance(password_age_days, bool)
                and password_age_days > STALE_CREDENTIAL_DAYS
            ) or (
                isinstance(password_last_used_days, int)
                and not isinstance(password_last_used_days, bool)
                and password_last_used_days > STALE_CREDENTIAL_DAYS
            )
            if password_is_stale:
                usage_evidence = (
                    f"has never been used and is {password_age_days} days old"
                    if password_last_used_days is None
                    else f"was last used {password_last_used_days} days ago"
                )
                _add_finding(
                    findings,
                    severity="medium",
                    rule_id="IAM-012",
                    resource_type=subject_type,
                    resource_id=subject_name,
                    title="Stale console password",
                    evidence=f"The active console password {usage_evidence}.",
                    impact=(
                        "Dormant console credentials increase the attack surface without "
                        "supporting recent user activity."
                    ),
                    remediation=(
                        "Confirm whether console access is still needed and remove the login "
                        "profile when it is not."
                    ),
                    references=[REF_AWS_IAM_BEST_PRACTICES, REF_AWS_CREDENTIAL_REPORT],
                    policy_name="credential-report",
                    statement_id="password-last-used",
                )

    findings.extend(analyze_permissions_boundary(subject_type, principal))

    if subject_type == "role":
        findings.extend(analyze_trust_policy(principal, account_id))

    return findings


def analyze_trust_policy(role: dict[str, Any], account_id: str) -> list[Finding]:
    findings: list[Finding] = []
    role_name = str(role.get("name", "unknown-role"))
    trust_policy = role.get("trust_policy", {})

    for index, statement in enumerate(_statements(trust_policy)):
        if _statement_effect(statement) != "allow" or not _allows_role_assumption(
            statement
        ):
            continue

        principal = statement.get("principal", statement.get("Principal", {}))
        not_principal = statement.get(
            "not_principal",
            statement.get("NotPrincipal"),
        )
        broad_not_principal = not_principal is not None
        external_principals = (
            [f"all principals except {json.dumps(not_principal, sort_keys=True)}"]
            if broad_not_principal
            else _external_principals(principal, account_id)
        )
        statement_id = _statement_id(statement, index)

        if external_principals:
            guardrails = _trust_guardrails(statement)
            public_principal = broad_not_principal or "*" in external_principals
            if public_principal:
                severity = "high" if guardrails else "critical"
                title = "Role trust allows every principal"
                impact = (
                    "Any principal can attempt to assume the role, subject only to the listed "
                    "conditions and caller-side permissions."
                )
            else:
                severity = "medium" if guardrails else "high"
                title = "Cross-account role trust"
                impact = "An external account or principal may be able to assume this role."
            _add_finding(
                findings,
                severity=severity,
                rule_id="IAM-008",
                resource_type="role",
                resource_id=role_name,
                title=title,
                evidence=(
                    "Trust policy allows external principal(s): "
                    f"{json.dumps(external_principals)}. Recognized guardrails: "
                    f"{', '.join(guardrails) if guardrails else 'none'}."
                ),
                impact=impact,
                remediation=(
                    "Restrict the trusted principal, require an external ID for third-party "
                    "access or an organization condition for internal multi-account access, "
                    "and confirm the business need."
                ),
                references=[
                    REF_MITRE_TRUSTED_RELATIONSHIP,
                    REF_AWS_IAM_BEST_PRACTICES,
                    REF_AWS_PRINCIPAL_ELEMENT,
                    REF_AWS_ROLE_EXTERNAL_ID,
                ],
                policy_name="trust-policy",
                statement_id=statement_id,
                extra_metadata={
                    "trust_guardrails": ", ".join(guardrails) if guardrails else "none"
                },
            )

    return findings


def analyze_environment(environment: dict[str, Any]) -> list[Finding]:
    account_id = str(environment.get("account_id", ""))
    findings: list[Finding] = []

    root_account = environment.get("root_account")
    if isinstance(root_account, dict):
        findings.extend(analyze_root_account(root_account))

    for user in environment.get("users", []):
        findings.extend(analyze_principal("user", user, account_id))

    for group in environment.get("groups", []):
        findings.extend(analyze_principal("group", group, account_id))

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
