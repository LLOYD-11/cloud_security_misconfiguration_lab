"""Deterministic benchmark evidence profiles for every built-in rule."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable

from cloud_findings import Finding
from cloud_security_lab.normalizers import (
    normalize_aws_cloudtrail_environment,
    normalize_aws_ec2_environment,
    normalize_aws_iam_environment,
    normalize_aws_s3_environment,
)
from cloudtrail_detector.detector import analyze_environment as analyze_cloudtrail
from iam_analyzer.analyzer import analyze_environment as analyze_iam
from network_analyzer.analyzer import analyze_environment as analyze_network
from storage_analyzer.analyzer import analyze_environment as analyze_storage

ACCOUNT_ID = "111122223333"
EXTERNAL_ACCOUNT_ID = "999988887777"
SUPPORTED_MODULES = ("iam", "storage", "network", "cloudtrail")
Analyzer = Callable[[dict[str, Any]], list[Finding]]

ANALYZERS: dict[str, Analyzer] = {
    "iam": analyze_iam,
    "storage": analyze_storage,
    "network": analyze_network,
    "cloudtrail": analyze_cloudtrail,
}


def _policy(statement: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy_name": "BenchmarkPolicy",
        "policy_source": "inline",
        "statements": [statement],
    }


def _iam_user(
    name: str,
    *,
    policies: list[dict[str, Any]] | None = None,
    password_enabled: bool = False,
    mfa_enabled: bool = True,
    access_keys: list[dict[str, Any]] | None = None,
    password_age_days: int | None = 1,
    password_last_used_days: int | None = 0,
) -> dict[str, Any]:
    return {
        "name": name,
        "password_enabled": password_enabled,
        "password_age_days": password_age_days,
        "password_last_used_days": password_last_used_days,
        "mfa_enabled": mfa_enabled,
        "access_keys": access_keys or [],
        "attached_policies": policies or [],
    }


def _iam_role(
    name: str,
    *,
    policies: list[dict[str, Any]] | None = None,
    trust_statements: list[dict[str, Any]] | None = None,
    boundary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    role = {
        "name": name,
        "trust_policy": {"statements": trust_statements or []},
        "attached_policies": policies or [],
    }
    if boundary is not None:
        role["permissions_boundary"] = boundary
    return role


def _iam_environment(
    *,
    users: list[dict[str, Any]] | None = None,
    roles: list[dict[str, Any]] | None = None,
    root_account: dict[str, Any] | None = None,
) -> dict[str, Any]:
    environment: dict[str, Any] = {
        "account_id": ACCOUNT_ID,
        "users": users or [],
        "groups": [],
        "roles": roles or [],
    }
    if root_account is not None:
        environment["root_account"] = root_account
    return environment


def _iam_statement_profile(
    rule_id: str,
    mode: str,
) -> dict[str, Any] | None:
    positive_statements: dict[str, tuple[str, dict[str, Any]]] = {
        "IAM-001": (
            "role",
            {"effect": "Allow", "action": "*", "resource": "*"},
        ),
        "IAM-002": (
            "role",
            {
                "effect": "Allow",
                "action": "ec2:*",
                "resource": (
                    f"arn:aws:ec2:ap-southeast-2:{ACCOUNT_ID}:instance/*"
                ),
            },
        ),
        "IAM-003": (
            "role",
            {"effect": "Allow", "action": "s3:GetObject", "resource": "*"},
        ),
        "IAM-004": (
            "role",
            {
                "effect": "Allow",
                "action": "s3:PutObject",
                "resource": "arn:aws:s3:::benchmark-*/*",
            },
        ),
        "IAM-005": (
            "user",
            {
                "effect": "Allow",
                "action": "iam:CreateUser",
                "resource": f"arn:aws:iam::{ACCOUNT_ID}:user/benchmark-*",
            },
        ),
        "IAM-009": (
            "role",
            {
                "effect": "Allow",
                "not_action": "iam:*",
                "resource": "arn:aws:s3:::benchmark-data/*",
            },
        ),
        "IAM-010": (
            "role",
            {
                "effect": "Allow",
                "action": "s3:GetObject",
                "not_resource": "arn:aws:s3:::benchmark-private/*",
            },
        ),
    }
    boundary_statements: dict[str, tuple[str, dict[str, Any]]] = {
        "IAM-001": (
            "role",
            {
                "effect": "Allow",
                "action": "*",
                "resource": f"arn:aws:iam::{ACCOUNT_ID}:role/benchmark",
            },
        ),
        "IAM-002": (
            "role",
            {
                "effect": "Allow",
                "action": "ec2:DescribeInstances",
                "resource": (
                    f"arn:aws:ec2:ap-southeast-2:{ACCOUNT_ID}:instance/benchmark"
                ),
            },
        ),
        "IAM-003": (
            "role",
            {
                "effect": "Allow",
                "action": "s3:GetObject",
                "resource": "arn:aws:s3:::benchmark-data/report.csv",
            },
        ),
        "IAM-004": (
            "role",
            {
                "effect": "Allow",
                "action": "s3:PutObject",
                "resource": "arn:aws:s3:::benchmark-data/exact-object",
            },
        ),
        "IAM-005": (
            "user",
            {
                "effect": "Allow",
                "action": "iam:CreateUser",
                "resource": f"arn:aws:iam::{ACCOUNT_ID}:user/benchmark-*",
                "condition": {
                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                },
            },
        ),
        "IAM-009": (
            "role",
            {
                "effect": "Deny",
                "not_action": "iam:*",
                "resource": "*",
            },
        ),
        "IAM-010": (
            "role",
            {
                "effect": "Deny",
                "action": "s3:GetObject",
                "not_resource": "arn:aws:s3:::benchmark-private/*",
            },
        ),
    }
    definitions = positive_statements if mode == "positive" else boundary_statements
    definition = definitions.get(rule_id)
    if definition is None:
        return None
    subject_type, statement = definition
    name = f"{mode.lower()}-{rule_id.lower()}"
    policies = [_policy(statement)]
    if subject_type == "user":
        return _iam_environment(users=[_iam_user(name, policies=policies)])
    return _iam_environment(roles=[_iam_role(name, policies=policies)])


def _iam_rule_environment(rule_id: str, mode: str) -> dict[str, Any]:
    statement_profile = _iam_statement_profile(rule_id, mode)
    if statement_profile is not None:
        return statement_profile

    name = f"{mode.lower()}-{rule_id.lower()}"
    if rule_id == "IAM-006":
        return _iam_environment(
            users=[
                _iam_user(
                    name,
                    password_enabled=mode == "positive",
                    mfa_enabled=False,
                )
            ]
        )
    if rule_id == "IAM-007":
        return _iam_environment(
            users=[
                _iam_user(
                    name,
                    access_keys=[
                        {
                            "id": "benchmark-key",
                            "status": "Active",
                            "age_days": 91 if mode == "positive" else 90,
                            "last_used_days": 0,
                        }
                    ],
                )
            ]
        )
    if rule_id == "IAM-008":
        trusted_account = EXTERNAL_ACCOUNT_ID if mode == "positive" else ACCOUNT_ID
        return _iam_environment(
            roles=[
                _iam_role(
                    name,
                    trust_statements=[
                        {
                            "effect": "Allow",
                            "principal": {
                                "AWS": f"arn:aws:iam::{trusted_account}:root"
                            },
                            "action": "sts:AssumeRole",
                        }
                    ],
                )
            ]
        )
    if rule_id == "IAM-011":
        age = 100 if mode == "positive" else 90
        last_used = 91 if mode == "positive" else 90
        return _iam_environment(
            users=[
                _iam_user(
                    name,
                    access_keys=[
                        {
                            "id": "benchmark-key",
                            "status": "Active",
                            "age_days": age,
                            "last_used_days": last_used,
                        }
                    ],
                )
            ]
        )
    if rule_id == "IAM-012":
        return _iam_environment(
            users=[
                _iam_user(
                    name,
                    password_enabled=True,
                    mfa_enabled=True,
                    password_age_days=100,
                    password_last_used_days=91 if mode == "positive" else 90,
                )
            ]
        )
    if rule_id == "IAM-013":
        return _iam_environment(
            root_account={
                "password_enabled": False,
                "password_age_days": None,
                "password_last_used_days": None,
                "mfa_enabled": True,
                "access_keys": [
                    {
                        "id": "root-key",
                        "status": "Active" if mode == "positive" else "Inactive",
                        "age_days": 1,
                        "last_used_days": 0,
                    }
                ],
            }
        )
    if rule_id == "IAM-014":
        return _iam_environment(
            root_account={
                "password_enabled": mode == "positive",
                "password_age_days": 1,
                "password_last_used_days": 0,
                "mfa_enabled": False,
                "access_keys": [],
            }
        )
    if rule_id == "IAM-015":
        action = "*" if mode == "positive" else "ec2:DescribeInstances"
        return _iam_environment(
            roles=[
                _iam_role(
                    name,
                    boundary={
                        "policy_arn": (
                            f"arn:aws:iam::{ACCOUNT_ID}:policy/BenchmarkBoundary"
                        ),
                        "policy_name": "BenchmarkBoundary",
                        "document_available": True,
                        "statements": [
                            {
                                "effect": "Allow",
                                "action": action,
                                "resource": "*",
                            }
                        ],
                    },
                )
            ]
        )
    raise ValueError(f"Unsupported IAM benchmark rule: {rule_id}.")


def _secure_bucket(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "region": "ap-southeast-2",
        "object_ownership": "BucketOwnerEnforced",
        "public_access_block": {
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        },
        "acl": {"grants": []},
        "bucket_policy": {"statements": []},
        "encryption": {"enabled": True, "algorithm": "aws:kms"},
        "versioning": {"status": "Enabled"},
    }


def _storage_rule_environment(rule_id: str, mode: str) -> dict[str, Any]:
    name = f"{mode.lower()}-{rule_id.lower()}-bucket"
    bucket = _secure_bucket(name)
    if rule_id == "STO-001" and mode == "positive":
        bucket["public_access_block"]["block_public_policy"] = False
    elif rule_id == "STO-002":
        bucket["acl"]["grants"] = [
            {"grantee": "AllUsers", "permission": "READ"}
        ]
        if mode == "positive":
            bucket["object_ownership"] = "BucketOwnerPreferred"
            bucket["public_access_block"]["block_public_acls"] = False
            bucket["public_access_block"]["ignore_public_acls"] = False
    elif rule_id == "STO-003":
        bucket["public_access_block"]["restrict_public_buckets"] = False
        statement: dict[str, Any] = {
            "effect": "Allow",
            "principal": "*",
            "action": "s3:GetObject",
            "resource": f"arn:aws:s3:::{name}/*",
        }
        if mode == "boundary":
            statement["condition"] = {
                "StringEquals": {"aws:SourceAccount": ACCOUNT_ID}
            }
        bucket["bucket_policy"]["statements"] = [statement]
    elif rule_id == "STO-004" and mode == "positive":
        bucket["encryption"] = {"enabled": False}
    elif rule_id == "STO-005" and mode == "positive":
        bucket["versioning"]["status"] = "Disabled"
    elif rule_id == "STO-006" and mode == "positive":
        bucket["object_ownership"] = "BucketOwnerPreferred"
    elif rule_id not in {
        "STO-001",
        "STO-002",
        "STO-003",
        "STO-004",
        "STO-005",
        "STO-006",
    }:
        raise ValueError(f"Unsupported storage benchmark rule: {rule_id}.")
    return {"account_id": ACCOUNT_ID, "buckets": [bucket]}


def _network_group(
    name: str,
    *,
    inbound_rules: list[dict[str, Any]],
    outbound_rules: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "id": f"sg-{name}",
        "name": name,
        "owner_id": ACCOUNT_ID,
        "inbound_rules": inbound_rules,
        "outbound_rules": outbound_rules,
    }


def _network_rule_environment(rule_id: str, mode: str) -> dict[str, Any]:
    name = f"{mode.lower()}-{rule_id.lower()}"
    inbound: list[dict[str, Any]] = []
    outbound: list[dict[str, Any]] = []
    if rule_id == "NET-001":
        inbound = [
            {
                "protocol": "tcp",
                "from_port": 22 if mode == "positive" else 21,
                "to_port": 22 if mode == "positive" else 21,
                "cidr": "0.0.0.0/0",
            }
        ]
    elif rule_id == "NET-002":
        inbound = [
            {
                "protocol": "-1" if mode == "positive" else "tcp",
                "from_port": None if mode == "positive" else 0,
                "to_port": None if mode == "positive" else 65534,
                "cidr": "0.0.0.0/0",
            }
        ]
    elif rule_id == "NET-003":
        outbound = [
            {
                "protocol": "-1" if mode == "positive" else "tcp",
                "from_port": None if mode == "positive" else 0,
                "to_port": None if mode == "positive" else 65534,
                "cidr": "0.0.0.0/0",
            }
        ]
    else:
        raise ValueError(f"Unsupported network benchmark rule: {rule_id}.")
    return {
        "account_id": ACCOUNT_ID,
        "region": "ap-southeast-2",
        "security_groups": [
            _network_group(
                name,
                inbound_rules=inbound,
                outbound_rules=outbound,
            )
        ],
    }


def _cloud_event(
    event_id: str,
    event_name: str,
    *,
    identity_type: str = "IAMUser",
    actor: str = "benchmark-user",
    request_parameters: dict[str, Any] | None = None,
    error_code: str | None = None,
    response_elements: dict[str, Any] | None = None,
    additional_event_data: dict[str, Any] | None = None,
    observed_at: str = "2026-06-30T01:00:00Z",
    source_ip: str = "192.0.2.10",
) -> dict[str, Any]:
    identity: dict[str, Any] = {"type": identity_type}
    if identity_type.lower() != "root":
        identity["userName"] = actor
    event: dict[str, Any] = {
        "eventID": event_id,
        "eventTime": observed_at,
        "eventSource": "benchmark.amazonaws.com",
        "eventName": event_name,
        "awsRegion": "ap-southeast-2",
        "sourceIPAddress": source_ip,
        "userIdentity": identity,
        "requestParameters": request_parameters or {},
    }
    if error_code is not None:
        event["errorCode"] = error_code
    if response_elements is not None:
        event["responseElements"] = response_elements
    if additional_event_data is not None:
        event["additionalEventData"] = additional_event_data
    return event


def _cloudtrail_rule_environment(rule_id: str, mode: str) -> dict[str, Any]:
    event_id = f"{mode.lower()}-{rule_id.lower()}"
    if rule_id == "CLD-006":
        count = 5 if mode == "positive" else 4
        events = [
            _cloud_event(
                f"{event_id}-{index}",
                "AssumeRole",
                actor="failure-benchmark",
                error_code="AccessDenied",
                observed_at=f"2026-06-30T01:0{index}:00Z",
                source_ip="192.0.2.44",
            )
            for index in range(count)
        ]
        return {"account_id": ACCOUNT_ID, "events": events}

    positive_specs: dict[str, dict[str, Any]] = {
        "CLD-001": {
            "event_name": "ConsoleLogin",
            "identity_type": "Root",
            "response_elements": {"ConsoleLogin": "Success"},
        },
        "CLD-002": {
            "event_name": "DeactivateMFADevice",
            "request_parameters": {"userName": "benchmark-user"},
        },
        "CLD-003": {
            "event_name": "AuthorizeSecurityGroupIngress",
            "request_parameters": {"groupId": "sg-benchmark"},
        },
        "CLD-004": {
            "event_name": "PutBucketPolicy",
            "request_parameters": {"bucketName": "benchmark-bucket"},
        },
        "CLD-005": {
            "event_name": "CreatePolicyVersion",
            "request_parameters": {
                "policyArn": f"arn:aws:iam::{ACCOUNT_ID}:policy/BenchmarkPolicy"
            },
        },
        "CLD-007": {
            "event_name": "ConsoleLogin",
            "response_elements": {"ConsoleLogin": "Success"},
            "additional_event_data": {"MFAUsed": "No"},
        },
        "CLD-008": {
            "event_name": "CreateAccessKey",
            "request_parameters": {"userName": "benchmark-target"},
        },
        "CLD-009": {
            "event_name": "UpdateAssumeRolePolicy",
            "request_parameters": {"roleName": "benchmark-role"},
        },
        "CLD-010": {
            "event_name": "StopLogging",
            "request_parameters": {"name": "benchmark-trail"},
        },
        "CLD-011": {
            "event_name": "ScheduleKeyDeletion",
            "request_parameters": {"keyId": "benchmark-key"},
        },
    }
    boundary_specs: dict[str, dict[str, Any]] = {
        "CLD-001": {
            "event_name": "ConsoleLogin",
            "identity_type": "Root",
            "response_elements": {"ConsoleLogin": "Failure"},
        },
        "CLD-002": {
            "event_name": "DeactivateMFADevice",
            "request_parameters": {"userName": "benchmark-user"},
            "error_code": "AccessDenied",
        },
        "CLD-003": {
            "event_name": "RevokeSecurityGroupIngress",
            "request_parameters": {"groupId": "sg-benchmark"},
        },
        "CLD-004": {
            "event_name": "DeleteBucketPolicy",
            "request_parameters": {"bucketName": "benchmark-bucket"},
        },
        "CLD-005": {
            "event_name": "DetachUserPolicy",
            "request_parameters": {"userName": "benchmark-user"},
        },
        "CLD-007": {
            "event_name": "ConsoleLogin",
            "response_elements": {"ConsoleLogin": "Success"},
            "additional_event_data": {"MFAUsed": "Yes"},
        },
        "CLD-008": {
            "event_name": "CreateAccessKey",
            "request_parameters": {"userName": "benchmark-target"},
            "error_code": "AccessDenied",
        },
        "CLD-009": {
            "event_name": "UpdateAssumeRolePolicy",
            "request_parameters": {"roleName": "benchmark-role"},
            "error_code": "AccessDenied",
        },
        "CLD-010": {
            "event_name": "StartLogging",
            "request_parameters": {"name": "benchmark-trail"},
        },
        "CLD-011": {
            "event_name": "EnableKey",
            "request_parameters": {"keyId": "benchmark-key"},
        },
    }
    specs = positive_specs if mode == "positive" else boundary_specs
    try:
        spec = dict(specs[rule_id])
    except KeyError as exc:
        raise ValueError(f"Unsupported CloudTrail benchmark rule: {rule_id}.") from exc
    event_name = str(spec.pop("event_name"))
    event = _cloud_event(event_id, event_name, **spec)
    return {"account_id": ACCOUNT_ID, "events": [event]}


def build_rule_environment(rule_id: str, mode: str) -> dict[str, Any]:
    """Build one positive or boundary profile for a cataloged rule."""

    if mode not in {"positive", "boundary"}:
        raise ValueError("Rule benchmark mode must be positive or boundary.")
    if rule_id.startswith("IAM-"):
        return _iam_rule_environment(rule_id, mode)
    if rule_id.startswith("STO-"):
        return _storage_rule_environment(rule_id, mode)
    if rule_id.startswith("NET-"):
        return _network_rule_environment(rule_id, mode)
    if rule_id.startswith("CLD-"):
        return _cloudtrail_rule_environment(rule_id, mode)
    raise ValueError(f"Unsupported benchmark rule ID: {rule_id}.")


def build_negative_environment(module: str) -> dict[str, Any]:
    """Build a hardened baseline expected to produce no findings."""

    if module == "iam":
        return _iam_environment(
            users=[_iam_user("hardened-readonly")],
            roles=[_iam_role("hardened-service-role")],
            root_account={
                "password_enabled": True,
                "password_age_days": 1,
                "password_last_used_days": 0,
                "mfa_enabled": True,
                "access_keys": [],
            },
        )
    if module == "storage":
        return {
            "account_id": ACCOUNT_ID,
            "buckets": [_secure_bucket("hardened-benchmark-bucket")],
        }
    if module == "network":
        return {
            "account_id": ACCOUNT_ID,
            "region": "ap-southeast-2",
            "security_groups": [
                _network_group(
                    "hardened-private",
                    inbound_rules=[
                        {
                            "protocol": "tcp",
                            "from_port": 443,
                            "to_port": 443,
                            "cidr": "10.0.0.0/16",
                        }
                    ],
                    outbound_rules=[
                        {
                            "protocol": "tcp",
                            "from_port": 443,
                            "to_port": 443,
                            "cidr": "10.0.0.0/16",
                        }
                    ],
                )
            ],
        }
    if module == "cloudtrail":
        return {
            "account_id": ACCOUNT_ID,
            "events": [
                _cloud_event(
                    "hardened-readonly-event",
                    "DescribeInstances",
                    actor="readonly-auditor",
                    source_ip="10.0.1.25",
                )
            ],
        }
    raise ValueError(f"Unsupported benchmark module: {module}.")


def run_malformed_profile(module: str) -> None:
    """Run one strict native adapter profile that must raise ValueError."""

    if module == "iam":
        normalize_aws_iam_environment(
            {"IsTruncated": True},
            {},
            as_of=date(2026, 6, 30),
        )
    elif module == "storage":
        normalize_aws_s3_environment({})
    elif module == "network":
        normalize_aws_ec2_environment(
            {"SecurityGroups": [], "NextToken": "next-page"}
        )
    elif module == "cloudtrail":
        normalize_aws_cloudtrail_environment(({"Records": []},))
    else:
        raise ValueError(f"Unsupported benchmark module: {module}.")
    raise AssertionError(f"Malformed {module} profile was unexpectedly accepted.")


def environment_for_profile(profile: str) -> tuple[str, dict[str, Any]]:
    """Resolve one non-malformed functional profile to module and environment."""

    parts = profile.split(":")
    if len(parts) == 3 and parts[0] == "rule":
        rule_id, mode = parts[1:]
        module = {
            "IAM": "iam",
            "STO": "storage",
            "NET": "network",
            "CLD": "cloudtrail",
        }[rule_id.split("-", 1)[0]]
        return module, build_rule_environment(rule_id, mode)
    if len(parts) == 3 and parts[0] == "module" and parts[2] == "negative":
        module = parts[1]
        return module, build_negative_environment(module)
    raise ValueError(f"Unsupported non-malformed benchmark profile: {profile}.")


def run_functional_profile(profile: str) -> list[Finding]:
    """Execute one functional profile and return its findings."""

    parts = profile.split(":")
    if len(parts) == 3 and parts[0] == "module" and parts[2] == "malformed":
        run_malformed_profile(parts[1])
        return []
    module, environment = environment_for_profile(profile)
    return ANALYZERS[module](environment)


def build_scale_environment(module: str, input_count: int) -> dict[str, Any]:
    """Build a deterministic 10-percent finding-rate scale corpus."""

    if input_count <= 0 or input_count % 10 != 0:
        raise ValueError("Scale input_count must be a positive multiple of 10.")
    if module == "iam":
        users = [
            _iam_user(
                f"scale-user-{index:05d}",
                password_enabled=index % 10 == 0,
                mfa_enabled=index % 10 != 0,
            )
            for index in range(input_count)
        ]
        return _iam_environment(users=users)
    if module == "storage":
        buckets = []
        for index in range(input_count):
            bucket = _secure_bucket(f"scale-bucket-{index:05d}")
            if index % 10 == 0:
                bucket["versioning"]["status"] = "Disabled"
            buckets.append(bucket)
        return {"account_id": ACCOUNT_ID, "buckets": buckets}
    if module == "network":
        groups = [
            _network_group(
                f"scale-{index:05d}",
                inbound_rules=[
                    {
                        "protocol": "tcp",
                        "from_port": 22 if index % 10 == 0 else 443,
                        "to_port": 22 if index % 10 == 0 else 443,
                        "cidr": "0.0.0.0/0" if index % 10 == 0 else "10.0.0.0/16",
                    }
                ],
                outbound_rules=[],
            )
            for index in range(input_count)
        ]
        return {
            "account_id": ACCOUNT_ID,
            "region": "ap-southeast-2",
            "security_groups": groups,
        }
    if module == "cloudtrail":
        base = datetime(2026, 6, 30, tzinfo=timezone.utc)
        events: list[dict[str, Any]] = []
        for group_index in range(input_count // 10):
            actor = f"scale-actor-{group_index:05d}"
            source_ip = f"192.0.2.{group_index % 254 + 1}"
            group_start = base + timedelta(minutes=group_index)
            for event_index in range(10):
                failed = event_index < 5
                events.append(
                    _cloud_event(
                        f"scale-{group_index:05d}-{event_index:02d}",
                        "AssumeRole" if failed else "DescribeInstances",
                        actor=actor,
                        source_ip=source_ip,
                        error_code="AccessDenied" if failed else None,
                        observed_at=(
                            group_start + timedelta(seconds=event_index)
                        ).isoformat().replace("+00:00", "Z"),
                    )
                )
        return {"account_id": ACCOUNT_ID, "events": events}
    raise ValueError(f"Unsupported benchmark module: {module}.")


def scale_input_count(module: str, environment: dict[str, Any]) -> int:
    """Return the resource or event count represented by a scale corpus."""

    keys = {
        "iam": "users",
        "storage": "buckets",
        "network": "security_groups",
        "cloudtrail": "events",
    }
    try:
        value = environment[keys[module]]
    except KeyError as exc:
        raise ValueError(f"Unsupported benchmark module: {module}.") from exc
    if not isinstance(value, list):
        raise ValueError(f"Scale profile for {module} does not contain a list.")
    return len(value)
