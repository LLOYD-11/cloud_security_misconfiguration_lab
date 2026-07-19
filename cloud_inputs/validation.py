"""Dependency-free validation for simplified analyzer environments."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn, cast

MODULE_LABELS = {
    "iam": "IAM",
    "storage": "storage",
    "network": "network",
    "cloudtrail": "CloudTrail",
}
RFC3339_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:[Zz]|[+-]\d{2}:\d{2})$"
)


class SimplifiedInputError(ValueError):
    """A stable, path-aware simplified-input contract error."""


def _fail(module: str, path: str, requirement: str) -> NoReturn:
    label = MODULE_LABELS[module]
    raise SimplifiedInputError(
        f"Invalid simplified {label} input at {path}: {requirement}."
    )


def _object(value: Any, module: str, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(module, path, "expected an object")
    return cast(dict[str, Any], value)


def _array(value: Any, module: str, path: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(module, path, "expected an array")
    return value


def _required(value: Mapping[str, Any], key: str, module: str, path: str) -> Any:
    if key not in value:
        _fail(module, f"{path}.{key}", "required field is missing")
    return value[key]


def _allowed(
    value: Mapping[str, Any],
    keys: set[str],
    module: str,
    path: str,
) -> None:
    unsupported = sorted(set(value) - keys)
    if unsupported:
        _fail(module, f"{path}.{unsupported[0]}", "unsupported field")


def _nonempty_string(value: Any, module: str, path: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(module, path, "expected a non-empty string")
    return value


def _string(value: Any, module: str, path: str) -> str:
    if not isinstance(value, str):
        _fail(module, path, "expected a string")
    return value


def _boolean(value: Any, module: str, path: str) -> bool:
    if not isinstance(value, bool):
        _fail(module, path, "expected a boolean")
    return value


def _integer(
    value: Any,
    module: str,
    path: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(module, path, "expected an integer")
    if minimum is not None and value < minimum:
        _fail(module, path, f"expected an integer greater than or equal to {minimum}")
    if maximum is not None and value > maximum:
        _fail(module, path, f"expected an integer less than or equal to {maximum}")
    return value


def _nullable_nonnegative_integer(value: Any, module: str, path: str) -> None:
    if value is not None:
        _integer(value, module, path, minimum=0)


def _enum(value: Any, allowed: set[str], module: str, path: str) -> str:
    candidate = _nonempty_string(value, module, path)
    if candidate not in allowed:
        choices = ", ".join(sorted(allowed))
        _fail(module, path, f"expected one of: {choices}")
    return candidate


def _account_id(value: Any, module: str, path: str) -> str:
    account_id = _nonempty_string(value, module, path)
    if len(account_id) != 12 or not account_id.isdigit():
        _fail(module, path, "expected a 12-digit AWS account ID")
    return account_id


def canonicalize_rfc3339_timestamp(value: Any, *, field_name: str) -> str:
    """Validate an offset-aware RFC 3339 value and return canonical UTC."""

    if (
        not isinstance(value, str)
        or not value
        or RFC3339_PATTERN.fullmatch(value) is None
        or value.endswith("-00:00")
    ):
        raise ValueError(
            f"{field_name} must be an RFC 3339 timestamp with a UTC offset."
        )
    normalized = (
        value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    )
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError) as exc:
        raise ValueError(
            f"{field_name} must be an RFC 3339 timestamp with a UTC offset."
        ) from exc


def _timestamp(value: Any, module: str, path: str) -> str:
    try:
        return canonicalize_rfc3339_timestamp(value, field_name=path)
    except ValueError:
        _fail(module, path, "expected an RFC 3339 timestamp with a UTC offset")


def _string_list(
    value: Any,
    module: str,
    path: str,
    *,
    nonempty: bool = False,
    unique: bool = False,
) -> list[Any]:
    items = _array(value, module, path)
    if nonempty and not items:
        _fail(module, path, "expected a non-empty array")
    for index, item in enumerate(items):
        _nonempty_string(item, module, f"{path}[{index}]")
    if unique and len(set(cast(list[str], items))) != len(items):
        _fail(module, path, "expected unique string values")
    return items


def _string_or_string_list(value: Any, module: str, path: str) -> None:
    if isinstance(value, str):
        _nonempty_string(value, module, path)
        return
    _string_list(value, module, path, nonempty=True)


def _aliased(
    value: Mapping[str, Any],
    canonical: str,
    compatibility: str,
    module: str,
    path: str,
) -> tuple[Any, str] | None:
    present = [key for key in (canonical, compatibility) if key in value]
    if len(present) > 1:
        _fail(
            module,
            path,
            f"must not define both {canonical!r} and {compatibility!r}",
        )
    if not present:
        return None
    key = present[0]
    return value[key], f"{path}.{key}"


def _statement_collection(
    value: Mapping[str, Any],
    module: str,
    path: str,
    validator: Callable[[Any, str, str], None],
) -> None:
    has_statements = "statements" in value
    has_document = "document" in value
    if has_statements and has_document:
        _fail(module, path, "must not define both 'statements' and 'document'")
    if not has_statements and not has_document:
        _fail(module, f"{path}.statements", "required field is missing")

    if has_statements:
        statements = _array(value["statements"], module, f"{path}.statements")
        statement_path = f"{path}.statements"
        singleton = False
    else:
        document = _object(value["document"], module, f"{path}.document")
        _allowed(
            document,
            {"Version", "Id", "Statement"},
            module,
            f"{path}.document",
        )
        for key in ("Version", "Id"):
            if key in document:
                _nonempty_string(
                    document[key],
                    module,
                    f"{path}.document.{key}",
                )
        raw_statements = _required(
            document,
            "Statement",
            module,
            f"{path}.document",
        )
        if isinstance(raw_statements, dict):
            statements = [raw_statements]
            singleton = True
        else:
            statements = _array(
                raw_statements,
                module,
                f"{path}.document.Statement",
            )
            singleton = False
        statement_path = f"{path}.document.Statement"

    for index, statement in enumerate(statements):
        item_path = statement_path if singleton else f"{statement_path}[{index}]"
        validator(statement, module, item_path)


def _iam_principal(value: Any, module: str, path: str) -> None:
    if isinstance(value, str):
        _nonempty_string(value, module, path)
        return
    principal = _object(value, module, path)
    if not principal:
        _fail(module, path, "expected at least one principal entry")
    for key in sorted(principal):
        _nonempty_string(key, module, f"{path} key")
        _string_or_string_list(principal[key], module, f"{path}.{key}")


def _iam_statement(value: Any, module: str, path: str) -> None:
    statement = _object(value, module, path)
    _allowed(
        statement,
        {
            "sid",
            "Sid",
            "effect",
            "Effect",
            "action",
            "Action",
            "not_action",
            "NotAction",
            "resource",
            "Resource",
            "not_resource",
            "NotResource",
            "principal",
            "Principal",
            "not_principal",
            "NotPrincipal",
            "condition",
            "Condition",
        },
        module,
        path,
    )
    sid = _aliased(statement, "sid", "Sid", module, path)
    if sid is not None:
        _string(sid[0], module, sid[1])

    effect = _aliased(statement, "effect", "Effect", module, path)
    if effect is None:
        _fail(module, f"{path}.effect", "required field is missing")
    _enum(effect[0], {"Allow", "Deny"}, module, effect[1])

    action = _aliased(statement, "action", "Action", module, path)
    not_action = _aliased(statement, "not_action", "NotAction", module, path)
    if (action is None) == (not_action is None):
        _fail(
            module,
            path,
            "expected exactly one of action/Action or not_action/NotAction",
        )
    for candidate in (action, not_action):
        if candidate is not None:
            _string_or_string_list(candidate[0], module, candidate[1])

    resource = _aliased(statement, "resource", "Resource", module, path)
    not_resource = _aliased(
        statement,
        "not_resource",
        "NotResource",
        module,
        path,
    )
    if resource is not None and not_resource is not None:
        _fail(
            module,
            path,
            "must not define both resource/Resource and not_resource/NotResource",
        )
    for candidate in (resource, not_resource):
        if candidate is not None:
            _string_or_string_list(candidate[0], module, candidate[1])

    principal = _aliased(statement, "principal", "Principal", module, path)
    not_principal = _aliased(
        statement,
        "not_principal",
        "NotPrincipal",
        module,
        path,
    )
    if principal is not None and not_principal is not None:
        _fail(
            module,
            path,
            "must not define both principal/Principal and not_principal/NotPrincipal",
        )
    for candidate in (principal, not_principal):
        if candidate is not None:
            _iam_principal(candidate[0], module, candidate[1])

    condition = _aliased(statement, "condition", "Condition", module, path)
    if condition is not None:
        _object(condition[0], module, condition[1])


def _iam_policy(value: Any, module: str, path: str) -> None:
    policy = _object(value, module, path)
    _allowed(
        policy,
        {
            "policy_name",
            "policy_arn",
            "policy_source",
            "statements",
            "document",
        },
        module,
        path,
    )
    _nonempty_string(
        _required(policy, "policy_name", module, path),
        module,
        f"{path}.policy_name",
    )
    if "policy_arn" in policy:
        _nonempty_string(policy["policy_arn"], module, f"{path}.policy_arn")
    if "policy_source" in policy:
        _enum(
            policy["policy_source"],
            {"inline", "managed"},
            module,
            f"{path}.policy_source",
        )
    _statement_collection(
        policy,
        module,
        path,
        _iam_statement,
    )


def _access_key(value: Any, module: str, path: str) -> None:
    access_key = _object(value, module, path)
    _allowed(
        access_key,
        {"id", "age_days", "last_used_days", "status"},
        module,
        path,
    )
    _nonempty_string(
        _required(access_key, "id", module, path),
        module,
        f"{path}.id",
    )
    _integer(
        _required(access_key, "age_days", module, path),
        module,
        f"{path}.age_days",
        minimum=0,
    )
    if "last_used_days" in access_key:
        _nullable_nonnegative_integer(
            access_key["last_used_days"],
            module,
            f"{path}.last_used_days",
        )
    if "status" in access_key:
        _enum(
            access_key["status"],
            {"Active", "Inactive", "active", "inactive"},
            module,
            f"{path}.status",
        )


def _access_keys(value: Any, module: str, path: str) -> None:
    for index, access_key in enumerate(_array(value, module, path)):
        _access_key(access_key, module, f"{path}[{index}]")


def _permissions_boundary(value: Any, module: str, path: str) -> None:
    boundary = _object(value, module, path)
    _allowed(
        boundary,
        {
            "policy_arn",
            "policy_name",
            "document_available",
            "statements",
            "document",
        },
        module,
        path,
    )
    for key in ("policy_arn", "policy_name"):
        _nonempty_string(
            _required(boundary, key, module, path),
            module,
            f"{path}.{key}",
        )
    _boolean(
        _required(boundary, "document_available", module, path),
        module,
        f"{path}.document_available",
    )
    _statement_collection(
        boundary,
        module,
        path,
        _iam_statement,
    )


def _iam_policies(value: Any, module: str, path: str) -> None:
    for index, policy in enumerate(_array(value, module, path)):
        _iam_policy(policy, module, f"{path}[{index}]")


def _credential_fields(value: Mapping[str, Any], module: str, path: str) -> None:
    _boolean(
        _required(value, "password_enabled", module, path),
        module,
        f"{path}.password_enabled",
    )
    for key in ("password_age_days", "password_last_used_days"):
        _nullable_nonnegative_integer(
            _required(value, key, module, path),
            module,
            f"{path}.{key}",
        )
    _boolean(
        _required(value, "mfa_enabled", module, path),
        module,
        f"{path}.mfa_enabled",
    )
    _access_keys(
        _required(value, "access_keys", module, path),
        module,
        f"{path}.access_keys",
    )


def _iam_user(value: Any, module: str, path: str) -> None:
    user = _object(value, module, path)
    _allowed(
        user,
        {
            "name",
            "groups",
            "password_enabled",
            "password_age_days",
            "password_last_used_days",
            "mfa_enabled",
            "access_keys",
            "attached_policies",
            "permissions_boundary",
        },
        module,
        path,
    )
    _nonempty_string(_required(user, "name", module, path), module, f"{path}.name")
    _boolean(
        _required(user, "mfa_enabled", module, path),
        module,
        f"{path}.mfa_enabled",
    )
    _access_keys(
        _required(user, "access_keys", module, path),
        module,
        f"{path}.access_keys",
    )
    _iam_policies(
        _required(user, "attached_policies", module, path),
        module,
        f"{path}.attached_policies",
    )
    if "groups" in user:
        _string_list(user["groups"], module, f"{path}.groups", unique=True)
    if "password_enabled" in user:
        _boolean(user["password_enabled"], module, f"{path}.password_enabled")
    for key in ("password_age_days", "password_last_used_days"):
        if key in user:
            _nullable_nonnegative_integer(user[key], module, f"{path}.{key}")
    if "permissions_boundary" in user:
        _permissions_boundary(
            user["permissions_boundary"],
            module,
            f"{path}.permissions_boundary",
        )


def _iam_group(value: Any, module: str, path: str) -> None:
    group = _object(value, module, path)
    _allowed(group, {"name", "members", "attached_policies"}, module, path)
    _nonempty_string(
        _required(group, "name", module, path),
        module,
        f"{path}.name",
    )
    _string_list(
        _required(group, "members", module, path),
        module,
        f"{path}.members",
        unique=True,
    )
    _iam_policies(
        _required(group, "attached_policies", module, path),
        module,
        f"{path}.attached_policies",
    )


def _iam_role(value: Any, module: str, path: str) -> None:
    role = _object(value, module, path)
    _allowed(
        role,
        {"name", "trust_policy", "attached_policies", "permissions_boundary"},
        module,
        path,
    )
    _nonempty_string(_required(role, "name", module, path), module, f"{path}.name")
    trust_policy = _object(
        _required(role, "trust_policy", module, path),
        module,
        f"{path}.trust_policy",
    )
    _allowed(
        trust_policy,
        {"statements", "document"},
        module,
        f"{path}.trust_policy",
    )
    _statement_collection(
        trust_policy,
        module,
        f"{path}.trust_policy",
        _iam_statement,
    )
    _iam_policies(
        _required(role, "attached_policies", module, path),
        module,
        f"{path}.attached_policies",
    )
    if "permissions_boundary" in role:
        _permissions_boundary(
            role["permissions_boundary"],
            module,
            f"{path}.permissions_boundary",
        )


def _iam_environment(value: Any) -> None:
    module = "iam"
    environment = _object(value, module, "$")
    _allowed(
        environment,
        {"account_id", "users", "groups", "roles", "root_account"},
        module,
        "$",
    )
    _account_id(
        _required(environment, "account_id", module, "$"),
        module,
        "$.account_id",
    )
    users = _array(
        _required(environment, "users", module, "$"),
        module,
        "$.users",
    )
    for index, user in enumerate(users):
        _iam_user(user, module, f"$.users[{index}]")
    if "groups" in environment:
        for index, group in enumerate(_array(environment["groups"], module, "$.groups")):
            _iam_group(group, module, f"$.groups[{index}]")
    roles = _array(
        _required(environment, "roles", module, "$"),
        module,
        "$.roles",
    )
    for index, role in enumerate(roles):
        _iam_role(role, module, f"$.roles[{index}]")
    if "root_account" in environment:
        root = _object(environment["root_account"], module, "$.root_account")
        _allowed(
            root,
            {
                "password_enabled",
                "password_age_days",
                "password_last_used_days",
                "mfa_enabled",
                "access_keys",
            },
            module,
            "$.root_account",
        )
        _credential_fields(root, module, "$.root_account")


def _storage_principal(value: Any, module: str, path: str) -> None:
    if isinstance(value, str):
        _nonempty_string(value, module, path)
        return
    if isinstance(value, list):
        _string_list(value, module, path, nonempty=True)
        return
    principal = _object(value, module, path)
    if not principal:
        _fail(module, path, "expected at least one principal entry")
    for key in sorted(principal):
        _nonempty_string(key, module, f"{path} key")
        _string_or_string_list(principal[key], module, f"{path}.{key}")


def _storage_statement(value: Any, module: str, path: str) -> None:
    statement = _object(value, module, path)
    _allowed(
        statement,
        {
            "sid",
            "Sid",
            "effect",
            "Effect",
            "principal",
            "Principal",
            "not_principal",
            "NotPrincipal",
            "action",
            "Action",
            "not_action",
            "NotAction",
            "resource",
            "Resource",
            "not_resource",
            "NotResource",
            "condition",
            "Condition",
        },
        module,
        path,
    )
    sid = _aliased(statement, "sid", "Sid", module, path)
    if sid is not None:
        _string(sid[0], module, sid[1])
    effect = _aliased(statement, "effect", "Effect", module, path)
    if effect is None:
        _fail(module, f"{path}.effect", "required field is missing")
    _enum(effect[0], {"Allow", "Deny"}, module, effect[1])

    alternatives = (
        (("principal", "Principal"), ("not_principal", "NotPrincipal"), _storage_principal),
        (("action", "Action"), ("not_action", "NotAction"), _string_or_string_list),
        (("resource", "Resource"), ("not_resource", "NotResource"), _string_or_string_list),
    )
    for first, second, validator in alternatives:
        first_value = _aliased(statement, first[0], first[1], module, path)
        second_value = _aliased(statement, second[0], second[1], module, path)
        if (first_value is None) == (second_value is None):
            _fail(
                module,
                path,
                f"expected exactly one of {first[0]}/{first[1]} or {second[0]}/{second[1]}",
            )
        candidate = first_value if first_value is not None else second_value
        assert candidate is not None
        validator(candidate[0], module, candidate[1])

    condition = _aliased(statement, "condition", "Condition", module, path)
    if condition is not None:
        _object(condition[0], module, condition[1])


def _storage_statements(value: Mapping[str, Any], module: str, path: str) -> None:
    has_canonical = "statements" in value
    has_compatibility = "Statement" in value
    if has_canonical and has_compatibility:
        _fail(module, path, "must not define both 'statements' and 'Statement'")
    if not has_canonical and not has_compatibility:
        _fail(module, f"{path}.statements", "required field is missing")

    key = "statements" if has_canonical else "Statement"
    raw_statements = value[key]
    if key == "Statement" and isinstance(raw_statements, dict):
        statements = [raw_statements]
        singleton = True
    else:
        statements = _array(raw_statements, module, f"{path}.{key}")
        singleton = False
    for index, statement in enumerate(statements):
        item_path = f"{path}.{key}"
        if not singleton:
            item_path += f"[{index}]"
        _storage_statement(statement, module, item_path)


def _storage_bucket(value: Any, module: str, path: str) -> None:
    bucket = _object(value, module, path)
    _allowed(
        bucket,
        {
            "name",
            "region",
            "object_ownership",
            "public_access_block",
            "acl",
            "bucket_policy",
            "encryption",
            "versioning",
        },
        module,
        path,
    )
    name = _nonempty_string(
        _required(bucket, "name", module, path),
        module,
        f"{path}.name",
    )
    if len(name) < 3:
        _fail(module, f"{path}.name", "expected at least 3 characters")
    if "region" in bucket:
        _nonempty_string(bucket["region"], module, f"{path}.region")
    if "object_ownership" in bucket:
        _enum(
            bucket["object_ownership"],
            {"BucketOwnerEnforced", "BucketOwnerPreferred", "ObjectWriter"},
            module,
            f"{path}.object_ownership",
        )

    public_access_block = _object(
        _required(bucket, "public_access_block", module, path),
        module,
        f"{path}.public_access_block",
    )
    controls = {
        "block_public_acls",
        "ignore_public_acls",
        "block_public_policy",
        "restrict_public_buckets",
    }
    _allowed(public_access_block, controls, module, f"{path}.public_access_block")
    for key in sorted(controls):
        _boolean(
            _required(public_access_block, key, module, f"{path}.public_access_block"),
            module,
            f"{path}.public_access_block.{key}",
        )

    acl = _object(
        _required(bucket, "acl", module, path),
        module,
        f"{path}.acl",
    )
    _allowed(acl, {"grants"}, module, f"{path}.acl")
    grants = _array(
        _required(acl, "grants", module, f"{path}.acl"),
        module,
        f"{path}.acl.grants",
    )
    for index, raw_grant in enumerate(grants):
        grant_path = f"{path}.acl.grants[{index}]"
        grant = _object(raw_grant, module, grant_path)
        _allowed(grant, {"grantee", "permission"}, module, grant_path)
        for key in ("grantee", "permission"):
            _nonempty_string(
                _required(grant, key, module, grant_path),
                module,
                f"{grant_path}.{key}",
            )

    policy = _object(
        _required(bucket, "bucket_policy", module, path),
        module,
        f"{path}.bucket_policy",
    )
    _allowed(
        policy,
        {"statements", "Version", "Id", "Statement"},
        module,
        f"{path}.bucket_policy",
    )
    for key in ("Version", "Id"):
        if key in policy:
            _nonempty_string(
                policy[key],
                module,
                f"{path}.bucket_policy.{key}",
            )
    _storage_statements(
        policy,
        module,
        f"{path}.bucket_policy",
    )

    encryption = _object(
        _required(bucket, "encryption", module, path),
        module,
        f"{path}.encryption",
    )
    _allowed(encryption, {"enabled", "algorithm", "key_id"}, module, f"{path}.encryption")
    _boolean(
        _required(encryption, "enabled", module, f"{path}.encryption"),
        module,
        f"{path}.encryption.enabled",
    )
    for key in ("algorithm", "key_id"):
        if key in encryption:
            _nonempty_string(encryption[key], module, f"{path}.encryption.{key}")

    versioning = _object(
        _required(bucket, "versioning", module, path),
        module,
        f"{path}.versioning",
    )
    _allowed(versioning, {"status"}, module, f"{path}.versioning")
    _enum(
        _required(versioning, "status", module, f"{path}.versioning"),
        {"Enabled", "Suspended", "Disabled"},
        module,
        f"{path}.versioning.status",
    )


def _storage_environment(value: Any) -> None:
    module = "storage"
    environment = _object(value, module, "$")
    _allowed(environment, {"account_id", "buckets"}, module, "$")
    _account_id(
        _required(environment, "account_id", module, "$"),
        module,
        "$.account_id",
    )
    buckets = _array(
        _required(environment, "buckets", module, "$"),
        module,
        "$.buckets",
    )
    for index, bucket in enumerate(buckets):
        _storage_bucket(bucket, module, f"$.buckets[{index}]")


def _network_direction(value: Any, module: str, path: str) -> None:
    direction = _object(value, module, path)
    _allowed(
        direction,
        {"status", "scope", "evidence", "resource_ids"},
        module,
        path,
    )
    _enum(
        _required(direction, "status", module, path),
        {"reachable", "not_reachable", "inconclusive"},
        module,
        f"{path}.status",
    )
    _nonempty_string(
        _required(direction, "scope", module, path),
        module,
        f"{path}.scope",
    )
    _string_list(
        _required(direction, "evidence", module, path),
        module,
        f"{path}.evidence",
        nonempty=True,
        unique=True,
    )
    if "resource_ids" in direction:
        _string_list(
            direction["resource_ids"],
            module,
            f"{path}.resource_ids",
            unique=True,
        )


def _network_reachability(value: Any, module: str, path: str) -> None:
    reachability = _object(value, module, path)
    _allowed(
        reachability,
        {"method", "observed_at", "ingress", "egress"},
        module,
        path,
    )
    _enum(
        _required(reachability, "method", module, path),
        {
            "aws-network-access-analyzer",
            "aws-reachability-analyzer",
            "manual-topology-review",
            "other",
        },
        module,
        f"{path}.method",
    )
    reachability["observed_at"] = _timestamp(
        _required(reachability, "observed_at", module, path),
        module,
        f"{path}.observed_at",
    )
    for direction in ("ingress", "egress"):
        _network_direction(
            _required(reachability, direction, module, path),
            module,
            f"{path}.{direction}",
        )


def _network_rule(value: Any, module: str, path: str) -> None:
    rule = _object(value, module, path)
    _allowed(
        rule,
        {
            "protocol",
            "from_port",
            "to_port",
            "cidr",
            "cidr_ip",
            "cidr_ipv6",
            "peer_type",
            "peer_id",
            "peer_account_id",
            "peer_vpc_id",
            "peering_status",
            "peer_group_name",
            "peer_vpc_peering_connection_id",
            "description",
        },
        module,
        path,
    )
    protocol = _required(rule, "protocol", module, path)
    if isinstance(protocol, str):
        _nonempty_string(protocol, module, f"{path}.protocol")
    elif not isinstance(protocol, int) or isinstance(protocol, bool):
        _fail(module, f"{path}.protocol", "expected a non-empty string or integer")

    ports: dict[str, int | None] = {}
    for key in ("from_port", "to_port"):
        port = _required(rule, key, module, path)
        if port is None:
            ports[key] = None
        else:
            ports[key] = _integer(
                port,
                module,
                f"{path}.{key}",
                minimum=-1,
                maximum=65535,
            )
    if (
        ports["from_port"] is not None
        and ports["to_port"] is not None
        and ports["from_port"] > ports["to_port"]
    ):
        _fail(module, path, "expected from_port to be less than or equal to to_port")

    cidr_keys = [
        key for key in ("cidr", "cidr_ip", "cidr_ipv6") if key in rule
    ]
    if len(cidr_keys) > 1:
        _fail(
            module,
            path,
            "must not define more than one of 'cidr', 'cidr_ip', and 'cidr_ipv6'",
        )
    has_cidr = bool(cidr_keys)
    has_peer_field = "peer_type" in rule or "peer_id" in rule
    if has_cidr == has_peer_field:
        _fail(module, path, "expected exactly one CIDR or peer target")
    if has_cidr:
        cidr_key = cidr_keys[0]
        cidr_path = f"{path}.{cidr_key}"
        cidr = _nonempty_string(rule[cidr_key], module, cidr_path)
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            _fail(module, cidr_path, "expected a valid IPv4 or IPv6 CIDR")
    else:
        _enum(
            _required(rule, "peer_type", module, path),
            {"prefix_list", "security_group"},
            module,
            f"{path}.peer_type",
        )
        _nonempty_string(
            _required(rule, "peer_id", module, path),
            module,
            f"{path}.peer_id",
        )

    if "peer_account_id" in rule:
        _account_id(rule["peer_account_id"], module, f"{path}.peer_account_id")
    for key in (
        "peer_vpc_id",
        "peering_status",
        "peer_group_name",
        "peer_vpc_peering_connection_id",
    ):
        if key in rule:
            _nonempty_string(rule[key], module, f"{path}.{key}")
    if "description" in rule:
        _string(rule["description"], module, f"{path}.description")


def _network_group(value: Any, module: str, path: str) -> None:
    group = _object(value, module, path)
    _allowed(
        group,
        {
            "id",
            "name",
            "description",
            "owner_id",
            "vpc_id",
            "arn",
            "tags",
            "reachability",
            "inbound_rules",
            "outbound_rules",
        },
        module,
        path,
    )
    for key in ("id", "name"):
        _nonempty_string(
            _required(group, key, module, path),
            module,
            f"{path}.{key}",
        )
    if "description" in group:
        _string(group["description"], module, f"{path}.description")
    if "owner_id" in group:
        _account_id(group["owner_id"], module, f"{path}.owner_id")
    for key in ("vpc_id", "arn"):
        if key in group:
            _nonempty_string(group[key], module, f"{path}.{key}")
    if "tags" in group:
        tags = _object(group["tags"], module, f"{path}.tags")
        for key in sorted(tags):
            _string(tags[key], module, f"{path}.tags.{key}")
    if "reachability" in group:
        _network_reachability(group["reachability"], module, f"{path}.reachability")
    for key in ("inbound_rules", "outbound_rules"):
        rules = _array(
            _required(group, key, module, path),
            module,
            f"{path}.{key}",
        )
        for index, rule in enumerate(rules):
            _network_rule(rule, module, f"{path}.{key}[{index}]")


def _network_environment(value: Any) -> None:
    module = "network"
    environment = _object(value, module, "$")
    _allowed(environment, {"account_id", "region", "security_groups"}, module, "$")
    _account_id(
        _required(environment, "account_id", module, "$"),
        module,
        "$.account_id",
    )
    if "region" in environment:
        _nonempty_string(environment["region"], module, "$.region")
    groups = _array(
        _required(environment, "security_groups", module, "$"),
        module,
        "$.security_groups",
    )
    for index, group in enumerate(groups):
        _network_group(group, module, f"$.security_groups[{index}]")


def _nullable_object(value: Any, module: str, path: str) -> None:
    if value is not None:
        _object(value, module, path)


def _cloudtrail_identity(value: Any, module: str, path: str) -> None:
    identity = _object(value, module, path)
    _nonempty_string(
        _required(identity, "type", module, path),
        module,
        f"{path}.type",
    )
    for key in ("userName", "arn", "principalId"):
        if key in identity:
            _nonempty_string(identity[key], module, f"{path}.{key}")
    if "accountId" in identity:
        _account_id(identity["accountId"], module, f"{path}.accountId")
    if "sessionContext" in identity:
        context = _object(identity["sessionContext"], module, f"{path}.sessionContext")
        if "sessionIssuer" in context:
            issuer = _object(
                context["sessionIssuer"],
                module,
                f"{path}.sessionContext.sessionIssuer",
            )
            for key in ("userName", "arn"):
                if key in issuer:
                    _nonempty_string(
                        issuer[key],
                        module,
                        f"{path}.sessionContext.sessionIssuer.{key}",
                    )


def _cloudtrail_event(value: Any, module: str, path: str) -> None:
    event = _object(value, module, path)
    if "eventID" in event:
        _nonempty_string(event["eventID"], module, f"{path}.eventID")
    event["eventTime"] = _timestamp(
        _required(event, "eventTime", module, path),
        module,
        f"{path}.eventTime",
    )
    for key in ("eventSource", "eventName", "sourceIPAddress"):
        _nonempty_string(
            _required(event, key, module, path),
            module,
            f"{path}.{key}",
        )
    _cloudtrail_identity(
        _required(event, "userIdentity", module, path),
        module,
        f"{path}.userIdentity",
    )
    for key in ("awsRegion", "userAgent"):
        if key in event:
            _nonempty_string(event[key], module, f"{path}.{key}")
    if "recipientAccountId" in event:
        _account_id(
            event["recipientAccountId"],
            module,
            f"{path}.recipientAccountId",
        )
    for key in ("requestParameters", "responseElements", "additionalEventData"):
        if key in event:
            _nullable_object(event[key], module, f"{path}.{key}")
    if "errorCode" in event:
        _nonempty_string(event["errorCode"], module, f"{path}.errorCode")
    if "errorMessage" in event:
        _string(event["errorMessage"], module, f"{path}.errorMessage")


def _cloudtrail_environment(value: Any) -> None:
    module = "cloudtrail"
    environment = _object(value, module, "$")
    _allowed(environment, {"account_id", "events"}, module, "$")
    _account_id(
        _required(environment, "account_id", module, "$"),
        module,
        "$.account_id",
    )
    events = _array(
        _required(environment, "events", module, "$"),
        module,
        "$.events",
    )
    for index, event in enumerate(events):
        _cloudtrail_event(event, module, f"$.events[{index}]")


VALIDATORS: dict[str, Callable[[Any], None]] = {
    "iam": _iam_environment,
    "storage": _storage_environment,
    "network": _network_environment,
    "cloudtrail": _cloudtrail_environment,
}


def _validator_for(module: str) -> Callable[[Any], None]:
    try:
        return VALIDATORS[module]
    except KeyError as exc:
        supported = ", ".join(sorted(VALIDATORS))
        raise ValueError(
            f"Unsupported simplified-input module {module!r}; expected one of: {supported}."
        ) from exc


def validate_simplified_environment(
    module: str,
    value: Any,
) -> dict[str, Any]:
    """Validate and return one simplified analyzer environment."""

    validator = _validator_for(module)
    validator(value)
    return cast(dict[str, Any], value)


def load_simplified_environment(path: Path, module: str) -> dict[str, Any]:
    """Load UTF-8 JSON and validate one simplified analyzer environment."""

    _validator_for(module)
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except json.JSONDecodeError as exc:
        _fail(
            module,
            "$",
            f"invalid JSON at line {exc.lineno} column {exc.colno}",
        )
    except UnicodeDecodeError:
        _fail(module, "$", "expected UTF-8 encoded JSON")
    return validate_simplified_environment(module, value)
