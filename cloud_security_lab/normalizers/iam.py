"""Normalize native AWS IAM exports into the lab's IAM environment contract."""

from __future__ import annotations

import base64
import binascii
import csv
import io
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from cloud_analysis import SkippedEvidence
from cloud_inputs import (
    enforce_collection_limit,
    load_bounded_json,
    parse_bounded_json_text,
    read_bounded_utf8,
    validate_analysis_input_limits,
    validate_json_value_limits,
)
from cloud_security_lab.normalizers.common import (
    write_normalized_environment as write_normalized_environment,
)

IAM_ARN_ACCOUNT_PATTERN = re.compile(r"^arn:[^:]+:iam::(\d{12}):")
ROOT_USER_NAMES = {"<root_account>", "root_account"}
CREDENTIAL_REQUIRED_COLUMNS = {
    "user",
    "arn",
    "password_enabled",
    "password_last_used",
    "password_last_changed",
    "mfa_active",
    "access_key_1_active",
    "access_key_1_last_rotated",
    "access_key_1_last_used_date",
    "access_key_2_active",
    "access_key_2_last_rotated",
    "access_key_2_last_used_date",
}
UNAVAILABLE_VALUES = {"", "n/a", "no_information", "not_supported"}


@dataclass(frozen=True)
class IamNormalizationResult:
    """Normalized analyzer input plus non-fatal evidence-quality warnings."""

    environment: dict[str, Any]
    warnings: tuple[str, ...]
    skipped_evidence: tuple[SkippedEvidence, ...] = ()


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    payload = load_bounded_json(path, label=label)
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must contain a JSON object.")
    return payload


def _object_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    if key not in payload:
        raise ValueError(f"AWS IAM authorization details are missing required field {key}.")
    value = payload[key]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"AWS IAM field {key} must be a list of objects.")
    return value


def _required_name(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} is missing a non-empty {key} value.")
    return value


def _decode_policy_document(value: Any, context: str) -> dict[str, Any]:
    current = value
    for _ in range(3):
        if isinstance(current, dict):
            return current
        if not isinstance(current, str):
            break

        try:
            current = parse_bounded_json_text(
                current,
                label=f"{context} IAM policy document",
            )
            continue
        except json.JSONDecodeError:
            decoded = unquote(current)
            if decoded == current:
                raise ValueError(f"{context} contains an invalid IAM policy document.")
            try:
                current = parse_bounded_json_text(
                    decoded,
                    label=f"{context} IAM policy document",
                )
            except json.JSONDecodeError as exc:
                raise ValueError(f"{context} contains an invalid IAM policy document.") from exc

    raise ValueError(f"{context} IAM policy document must decode to a JSON object.")


def _normalize_statement(statement: dict[str, Any]) -> dict[str, Any]:
    key_map = {
        "Sid": "sid",
        "Effect": "effect",
        "Action": "action",
        "NotAction": "not_action",
        "Resource": "resource",
        "NotResource": "not_resource",
        "Principal": "principal",
        "NotPrincipal": "not_principal",
        "Condition": "condition",
    }
    return {key_map.get(key, key): value for key, value in statement.items()}


def _normalize_policy_document(value: Any, context: str) -> list[dict[str, Any]]:
    document = _decode_policy_document(value, context)
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not all(
        isinstance(statement, dict) for statement in statements
    ):
        raise ValueError(f"{context} Statement must be an object or list of objects.")
    return [_normalize_statement(statement) for statement in statements]


def _managed_policy_documents(
    policies: list[dict[str, Any]],
    warnings: list[str],
) -> dict[str, dict[str, Any]]:
    managed: dict[str, dict[str, Any]] = {}
    seen_arns: set[str] = set()
    for policy in policies:
        arn = _required_name(policy, "Arn", "Managed policy")
        if arn in seen_arns:
            raise ValueError(f"AWS authorization details contain duplicate managed policy {arn}.")
        seen_arns.add(arn)
        versions = policy.get("PolicyVersionList", [])
        if not isinstance(versions, list) or not all(
            isinstance(version, dict) for version in versions
        ):
            raise ValueError(f"Managed policy {arn} PolicyVersionList must be a list of objects.")

        default_version_id = policy.get("DefaultVersionId")
        selected = next(
            (version for version in versions if version.get("IsDefaultVersion") is True),
            None,
        )
        if selected is None and default_version_id is not None:
            selected = next(
                (
                    version
                    for version in versions
                    if version.get("VersionId") == default_version_id
                ),
                None,
            )
        if selected is None or "Document" not in selected:
            warnings.append(f"Managed policy {arn} has no readable default policy version.")
            continue
        managed[arn] = {
            "policy_name": str(policy.get("PolicyName") or arn.rsplit("/", 1)[-1]),
            "statements": _normalize_policy_document(
                selected["Document"],
                f"Managed policy {arn}",
            ),
        }
    return managed


def _identity_policies(
    identity: dict[str, Any],
    *,
    inline_key: str,
    managed: dict[str, dict[str, Any]],
    context: str,
    warnings: list[str],
    skipped_evidence: list[SkippedEvidence],
) -> list[dict[str, Any]]:
    policies: list[dict[str, Any]] = []
    inline_policies = identity.get(inline_key, [])
    if not isinstance(inline_policies, list) or not all(
        isinstance(policy, dict) for policy in inline_policies
    ):
        raise ValueError(f"{context} {inline_key} must be a list of objects.")

    for policy in inline_policies:
        policy_name = _required_name(policy, "PolicyName", f"{context} inline policy")
        if "PolicyDocument" not in policy:
            raise ValueError(f"{context} inline policy {policy_name} is missing PolicyDocument.")
        policies.append(
            {
                "policy_name": policy_name,
                "policy_source": "inline",
                "statements": _normalize_policy_document(
                    policy["PolicyDocument"],
                    f"{context} inline policy {policy_name}",
                ),
            }
        )

    attachments = identity.get("AttachedManagedPolicies", [])
    if not isinstance(attachments, list) or not all(
        isinstance(attachment, dict) for attachment in attachments
    ):
        raise ValueError(f"{context} AttachedManagedPolicies must be a list of objects.")
    for attachment in attachments:
        arn = _required_name(attachment, "PolicyArn", f"{context} managed policy attachment")
        policy = managed.get(arn)
        if policy is None:
            warnings.append(f"{context} references managed policy {arn}, but its document is absent.")
            skipped_evidence.append(
                SkippedEvidence(
                    code="IAM_REFERENCED_POLICY_DOCUMENT_ABSENT",
                    evidence_type="managed-policy-document",
                    reason=(
                        "A referenced managed-policy document was absent, so its statements "
                        "were not evaluated."
                    ),
                    count=1,
                    affects_coverage=True,
                    resource_ids=[f"{context}/{arn}"],
                )
            )
            continue
        policies.append(
            {
                "policy_name": policy["policy_name"],
                "policy_arn": arn,
                "policy_source": "managed",
                "statements": policy["statements"],
            }
        )
    return policies


def _permissions_boundary(
    identity: dict[str, Any],
    *,
    managed: dict[str, dict[str, Any]],
    context: str,
    warnings: list[str],
) -> dict[str, Any] | None:
    value = identity.get("PermissionsBoundary")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{context} PermissionsBoundary must be an object.")

    boundary_type = value.get("PermissionsBoundaryType")
    if boundary_type != "PermissionsBoundaryPolicy":
        raise ValueError(
            f"{context} PermissionsBoundaryType must be PermissionsBoundaryPolicy."
        )
    arn = _required_name(
        value,
        "PermissionsBoundaryArn",
        f"{context} permissions boundary",
    )
    policy = managed.get(arn)
    if policy is None:
        warnings.append(
            f"{context} references permissions boundary {arn}, but its document is absent."
        )
        return {
            "policy_arn": arn,
            "policy_name": arn.rsplit("/", 1)[-1],
            "document_available": False,
            "statements": [],
        }
    return {
        "policy_arn": arn,
        "policy_name": policy["policy_name"],
        "document_available": True,
        "statements": policy["statements"],
    }


def _credential_csv_text(path: Path) -> str:
    raw = read_bounded_utf8(
        path,
        label=f"AWS credential report {path}",
    ).removeprefix("\ufeff")
    if not raw.lstrip().startswith(("{", "[")):
        return raw

    try:
        payload = parse_bounded_json_text(
            raw,
            label=f"AWS credential report {path}",
        )
    except json.JSONDecodeError as exc:
        raise ValueError("AWS credential report JSON is invalid.") from exc
    if not isinstance(payload, dict):
        raise ValueError("AWS credential report JSON must contain an object.")
    report_format = payload.get("ReportFormat")
    if report_format is not None and report_format != "text/csv":
        raise ValueError("AWS credential report ReportFormat must be text/csv.")
    content = payload.get("Content")
    if not isinstance(content, str) or not content:
        raise ValueError("AWS credential report JSON is missing Base64 Content.")
    try:
        compact_content = "".join(content.split())
        return base64.b64decode(compact_content, validate=True).decode("utf-8-sig")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError("AWS credential report Content is not valid Base64 UTF-8 CSV.") from exc


def _credential_rows(path: Path) -> dict[str, dict[str, str]]:
    reader = csv.DictReader(io.StringIO(_credential_csv_text(path)))
    fieldnames = set(reader.fieldnames or [])
    missing_columns = sorted(CREDENTIAL_REQUIRED_COLUMNS - fieldnames)
    if missing_columns:
        raise ValueError(
            "AWS credential report is missing required column(s): "
            + ", ".join(missing_columns)
        )

    rows: dict[str, dict[str, str]] = {}
    for row in reader:
        if None in row:
            raise ValueError("AWS credential report contains a row with extra CSV fields.")
        username = str(row.get("user", "")).strip()
        if not username:
            raise ValueError("AWS credential report contains a row without a user value.")
        if username in rows:
            raise ValueError(f"AWS credential report contains duplicate user {username}.")
        rows[username] = {key: str(value or "").strip() for key, value in row.items()}
        enforce_collection_limit(
            len(rows),
            label="AWS credential report",
        )
    return rows


def _validate_credential_rows(credential_rows: dict[str, dict[str, str]]) -> None:
    for username, row in credential_rows.items():
        if not isinstance(username, str) or not username:
            raise ValueError("AWS credential rows must use non-empty user names as keys.")
        if not isinstance(row, dict):
            raise ValueError(f"AWS credential row for {username} must be an object.")
        missing_columns = sorted(CREDENTIAL_REQUIRED_COLUMNS - set(row))
        if missing_columns:
            raise ValueError(
                f"AWS credential row for {username} is missing required field(s): "
                + ", ".join(missing_columns)
            )
        invalid_columns = sorted(
            field for field in CREDENTIAL_REQUIRED_COLUMNS if not isinstance(row[field], str)
        )
        if invalid_columns:
            raise ValueError(
                f"AWS credential row for {username} has non-string field(s): "
                + ", ".join(invalid_columns)
            )
        if row["user"] != username:
            raise ValueError(
                f"AWS credential row key {username} does not match its user value {row['user']}."
            )


def _report_boolean(value: str, context: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise ValueError(f"{context} must be TRUE or FALSE.")


def _report_date(value: str, context: str) -> date | None:
    normalized = value.strip().lower()
    if normalized in UNAVAILABLE_VALUES:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{context} must be an ISO 8601 timestamp or N/A.") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.date()


def _days_since(value: str, as_of: date, context: str) -> int | None:
    parsed = _report_date(value, context)
    if parsed is None:
        return None
    days = (as_of - parsed).days
    if days < 0:
        raise ValueError(f"{context} occurs after the analysis date {as_of.isoformat()}.")
    return days


def _user_credentials(row: dict[str, str], as_of: date, username: str) -> dict[str, Any]:
    access_keys: list[dict[str, Any]] = []
    for slot in (1, 2):
        active_key = f"access_key_{slot}_active"
        if not _report_boolean(row[active_key], f"{username} {active_key}"):
            continue

        rotated_key = f"access_key_{slot}_last_rotated"
        age_days = _days_since(row[rotated_key], as_of, f"{username} {rotated_key}")
        if age_days is None:
            raise ValueError(f"{username} has an active access key without {rotated_key}.")
        key: dict[str, Any] = {
            "id": f"credential-report:key-{slot}",
            "status": "Active",
            "age_days": age_days,
        }
        last_used_key = f"access_key_{slot}_last_used_date"
        last_used_days = _days_since(row[last_used_key], as_of, f"{username} {last_used_key}")
        key["last_used_days"] = last_used_days
        access_keys.append(key)

    password_enabled = _report_boolean(
        row["password_enabled"],
        f"{username} password_enabled",
    )
    password_age_days = _days_since(
        row["password_last_changed"],
        as_of,
        f"{username} password_last_changed",
    )
    if password_enabled and password_age_days is None:
        raise ValueError(f"{username} has an active password without password_last_changed.")

    return {
        "password_enabled": password_enabled,
        "password_age_days": password_age_days,
        "password_last_used_days": _days_since(
            row["password_last_used"],
            as_of,
            f"{username} password_last_used",
        ),
        "mfa_enabled": _report_boolean(row["mfa_active"], f"{username} mfa_active"),
        "access_keys": access_keys,
    }


def _account_id_from_arn(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = IAM_ARN_ACCOUNT_PATTERN.match(value)
    return match.group(1) if match else None


def _account_id(
    users: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    roles: list[dict[str, Any]],
    policies: list[dict[str, Any]],
    credential_rows: dict[str, dict[str, str]],
) -> str:
    candidates = {
        account_id
        for account_id in (
            *(_account_id_from_arn(item.get("Arn")) for item in users + groups + roles + policies),
            *(_account_id_from_arn(row.get("arn")) for row in credential_rows.values()),
        )
        if account_id is not None
    }
    if not candidates:
        raise ValueError("Unable to infer a 12-digit AWS account ID from IAM ARNs.")
    if len(candidates) != 1:
        raise ValueError(
            "AWS IAM inputs contain conflicting account IDs: " + ", ".join(sorted(candidates))
        )
    return candidates.pop()


def normalize_aws_iam_environment(
    authorization_details: dict[str, Any],
    credential_rows: dict[str, dict[str, str]],
    *,
    as_of: date,
) -> IamNormalizationResult:
    """Convert AWS authorization details and credential rows to analyzer input."""

    validate_json_value_limits(
        authorization_details,
        label="AWS IAM authorization details",
    )
    validate_json_value_limits(
        credential_rows,
        label="AWS IAM credential rows",
    )
    if authorization_details.get("IsTruncated") is True:
        raise ValueError(
            "AWS IAM authorization details are truncated; collect all pages before analysis."
        )
    if authorization_details.get("IsTruncated") is not False:
        raise ValueError(
            "AWS IAM authorization details must contain IsTruncated set to false."
        )

    _validate_credential_rows(credential_rows)

    users = _object_list(authorization_details, "UserDetailList")
    groups = _object_list(authorization_details, "GroupDetailList")
    roles = _object_list(authorization_details, "RoleDetailList")
    policies = _object_list(authorization_details, "Policies")
    enforce_collection_limit(
        len(users) + len(groups) + len(roles),
        label="AWS IAM identity inventory",
    )
    enforce_collection_limit(
        len(policies),
        label="AWS IAM managed policy inventory",
    )
    enforce_collection_limit(
        len(credential_rows),
        label="AWS IAM credential rows",
    )
    warnings: list[str] = []
    skipped_evidence: list[SkippedEvidence] = []
    managed = _managed_policy_documents(policies, warnings)

    group_policies: dict[str, list[dict[str, Any]]] = {}
    group_members: dict[str, list[str]] = {}
    for group in groups:
        group_name = _required_name(group, "GroupName", "IAM group")
        if group_name in group_policies:
            raise ValueError(f"AWS authorization details contain duplicate group {group_name}.")
        group_policies[group_name] = _identity_policies(
            group,
            inline_key="GroupPolicyList",
            managed=managed,
            context=f"Group {group_name}",
            warnings=warnings,
            skipped_evidence=skipped_evidence,
        )
        group_members[group_name] = []

    normalized_users: list[dict[str, Any]] = []
    seen_users: set[str] = set()
    user_credential_rows = {
        username: row
        for username, row in credential_rows.items()
        if username not in ROOT_USER_NAMES
    }
    for user in users:
        username = _required_name(user, "UserName", "IAM user")
        if username in seen_users:
            raise ValueError(f"AWS authorization details contain duplicate user {username}.")
        seen_users.add(username)
        credential_row = user_credential_rows.get(username)
        if credential_row is None:
            raise ValueError(f"AWS credential report has no row for IAM user {username}.")

        attached_policies = _identity_policies(
            user,
            inline_key="UserPolicyList",
            managed=managed,
            context=f"User {username}",
            warnings=warnings,
            skipped_evidence=skipped_evidence,
        )
        group_names = user.get("GroupList", [])
        if not isinstance(group_names, list) or not all(
            isinstance(group_name, str) for group_name in group_names
        ):
            raise ValueError(f"User {username} GroupList must be a list of strings.")
        if len(group_names) != len(set(group_names)):
            raise ValueError(f"User {username} GroupList contains duplicate group names.")
        for group_name in group_names:
            inherited = group_policies.get(group_name)
            if inherited is None:
                warnings.append(
                    f"User {username} references group {group_name}, but its detail is absent."
                )
                continue
            group_members[group_name].append(username)

        credentials = _user_credentials(credential_row, as_of, username)
        normalized_user = {
            "name": username,
            "groups": group_names,
            "password_enabled": credentials["password_enabled"],
            "password_age_days": credentials["password_age_days"],
            "password_last_used_days": credentials["password_last_used_days"],
            "mfa_enabled": credentials["mfa_enabled"],
            "access_keys": credentials["access_keys"],
            "attached_policies": attached_policies,
        }
        boundary = _permissions_boundary(
            user,
            managed=managed,
            context=f"User {username}",
            warnings=warnings,
        )
        if boundary is not None:
            normalized_user["permissions_boundary"] = boundary
        normalized_users.append(normalized_user)

    extra_credential_users = sorted(set(user_credential_rows) - seen_users)
    if extra_credential_users:
        warnings.append(
            "Credential report user(s) absent from authorization details: "
            + ", ".join(extra_credential_users)
        )
        skipped_evidence.append(
            SkippedEvidence(
                code="IAM_IDENTITY_DETAIL_ABSENT",
                evidence_type="iam-identity-detail",
                reason=(
                    "Credential-report identities absent from authorization details could not "
                    "be evaluated for permissions."
                ),
                count=len(extra_credential_users),
                affects_coverage=True,
                resource_ids=extra_credential_users,
            )
        )

    normalized_roles: list[dict[str, Any]] = []
    seen_roles: set[str] = set()
    for role in roles:
        role_name = _required_name(role, "RoleName", "IAM role")
        if role_name in seen_roles:
            raise ValueError(f"AWS authorization details contain duplicate role {role_name}.")
        seen_roles.add(role_name)
        if "AssumeRolePolicyDocument" not in role:
            raise ValueError(f"Role {role_name} is missing AssumeRolePolicyDocument.")
        normalized_role = {
            "name": role_name,
            "trust_policy": {
                "statements": _normalize_policy_document(
                    role["AssumeRolePolicyDocument"],
                    f"Role {role_name} trust policy",
                )
            },
            "attached_policies": _identity_policies(
                role,
                inline_key="RolePolicyList",
                managed=managed,
                context=f"Role {role_name}",
                warnings=warnings,
                skipped_evidence=skipped_evidence,
            ),
        }
        boundary = _permissions_boundary(
            role,
            managed=managed,
            context=f"Role {role_name}",
            warnings=warnings,
        )
        if boundary is not None:
            normalized_role["permissions_boundary"] = boundary
        normalized_roles.append(normalized_role)

    normalized_groups = [
        {
            "name": group_name,
            "members": sorted(group_members[group_name]),
            "attached_policies": group_policies[group_name],
        }
        for group_name in sorted(group_policies)
    ]

    root_rows = [
        credential_rows[username]
        for username in sorted(ROOT_USER_NAMES)
        if username in credential_rows
    ]
    if len(root_rows) > 1:
        raise ValueError("AWS credential report contains multiple root account rows.")
    root_account = (
        _user_credentials(root_rows[0], as_of, str(root_rows[0]["user"]))
        if root_rows
        else None
    )

    environment: dict[str, Any] = {
        "account_id": _account_id(users, groups, roles, policies, credential_rows),
        "users": normalized_users,
        "groups": normalized_groups,
        "roles": normalized_roles,
    }
    if root_account is not None:
        environment["root_account"] = root_account
    validate_analysis_input_limits("iam", environment)

    return IamNormalizationResult(
        environment=environment,
        warnings=tuple(warnings),
        skipped_evidence=tuple(skipped_evidence),
    )


def load_aws_iam_environment(
    authorization_details_path: Path,
    credential_report_path: Path,
    *,
    as_of: date,
) -> IamNormalizationResult:
    """Load native AWS exports and normalize them for the IAM analyzer."""

    authorization_details = _load_json_object(
        authorization_details_path,
        "AWS IAM authorization details file",
    )
    return normalize_aws_iam_environment(
        authorization_details,
        _credential_rows(credential_report_path),
        as_of=as_of,
    )
