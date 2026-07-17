"""Normalize native EC2 security group responses into the network contract."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cloud_analysis import SkippedEvidence

ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
SECURITY_GROUP_ID_PATTERN = re.compile(r"^sg-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
VPC_ID_PATTERN = re.compile(r"^vpc-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
PREFIX_LIST_ID_PATTERN = re.compile(r"^pl-[0-9a-f]+$")
VPC_PEERING_CONNECTION_ID_PATTERN = re.compile(r"^pcx-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
SECURITY_GROUP_ARN_PATTERN = re.compile(
    r"^arn:[^:]+:ec2:[^:]+:(\d{12}):security-group/"
    r"(sg-(?:[0-9a-f]{8}|[0-9a-f]{17}))$"
)
PORT_PROTOCOLS = {"tcp", "udp", "6", "17"}
ICMP_PROTOCOLS = {"icmp", "icmpv6", "1", "58"}
NAMED_PROTOCOLS = {"tcp", "udp", "icmp", "icmpv6", "-1"}


@dataclass(frozen=True)
class Ec2NormalizationResult:
    """Normalized network input plus non-fatal evidence-boundary warnings."""

    environment: dict[str, Any]
    warnings: tuple[str, ...]
    skipped_evidence: tuple[SkippedEvidence, ...] = ()


def _load_json_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("AWS EC2 security group export must contain a JSON object.")
    return payload


def _required_string(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} is missing a non-empty {key} value.")
    return value


def _optional_string(payload: dict[str, Any], key: str, context: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} field {key} must be a non-empty string when present.")
    return value


def _object_list(
    payload: dict[str, Any],
    key: str,
    context: str,
    *,
    required: bool = False,
) -> list[dict[str, Any]]:
    if key not in payload and not required:
        return []
    value = payload.get(key)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{context} field {key} must be a list of objects.")
    return value


def _validated_id(value: str, pattern: re.Pattern[str], context: str) -> str:
    if not pattern.fullmatch(value):
        raise ValueError(f"{context} has an invalid AWS identifier: {value}.")
    return value


def _normalized_ports(permission: dict[str, Any], context: str) -> tuple[str, int | None, int | None]:
    protocol = _required_string(permission, "IpProtocol", context).lower()
    if protocol not in NAMED_PROTOCOLS:
        try:
            protocol_number = int(protocol)
        except ValueError as exc:
            raise ValueError(f"{context} IpProtocol must be a supported name or number.") from exc
        if not 0 <= protocol_number <= 255:
            raise ValueError(f"{context} numeric IpProtocol must be between 0 and 255.")
        protocol = str(protocol_number)
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    if protocol in PORT_PROTOCOLS:
        if type(from_port) is not int or type(to_port) is not int:
            raise ValueError(f"{context} TCP/UDP permission requires integer port bounds.")
        if not 0 <= from_port <= to_port <= 65535:
            raise ValueError(f"{context} TCP/UDP port range must be within 0-65535 and ordered.")
        return protocol, from_port, to_port

    if protocol in ICMP_PROTOCOLS:
        if from_port is None and to_port is None and protocol in {"icmpv6", "58"}:
            return protocol, None, None
        if type(from_port) is not int or type(to_port) is not int:
            raise ValueError(f"{context} ICMP permission requires both type and code values.")
        if not -1 <= from_port <= 255 or not -1 <= to_port <= 255:
            raise ValueError(f"{context} ICMP type and code must be between -1 and 255.")
        if from_port == -1 and to_port != -1:
            raise ValueError(f"{context} all ICMP types requires code -1.")
        return protocol, from_port, to_port

    return protocol, None, None


def _description(payload: dict[str, Any], context: str) -> str | None:
    return _optional_string(payload, "Description", context)


def _base_rule(
    protocol: str,
    from_port: int | None,
    to_port: int | None,
    description: str | None,
) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "protocol": protocol,
        "from_port": from_port,
        "to_port": to_port,
    }
    if description is not None:
        rule["description"] = description
    return rule


def _cidr_rule(
    payload: dict[str, Any],
    *,
    cidr_key: str,
    version: int,
    context: str,
    protocol: str,
    from_port: int | None,
    to_port: int | None,
) -> dict[str, Any]:
    cidr = _required_string(payload, cidr_key, context)
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"{context} field {cidr_key} is not a valid CIDR.") from exc
    if network.version != version:
        raise ValueError(f"{context} field {cidr_key} is not IPv{version}.")
    rule = _base_rule(protocol, from_port, to_port, _description(payload, context))
    rule["cidr"] = str(network)
    return rule


def _prefix_list_rule(
    payload: dict[str, Any],
    *,
    context: str,
    protocol: str,
    from_port: int | None,
    to_port: int | None,
) -> dict[str, Any]:
    prefix_list_id = _validated_id(
        _required_string(payload, "PrefixListId", context),
        PREFIX_LIST_ID_PATTERN,
        context,
    )
    rule = _base_rule(protocol, from_port, to_port, _description(payload, context))
    rule.update({"peer_type": "prefix_list", "peer_id": prefix_list_id})
    return rule


def _security_group_rule(
    payload: dict[str, Any],
    *,
    context: str,
    protocol: str,
    from_port: int | None,
    to_port: int | None,
) -> dict[str, Any]:
    group_id = _validated_id(
        _required_string(payload, "GroupId", context),
        SECURITY_GROUP_ID_PATTERN,
        context,
    )
    rule = _base_rule(protocol, from_port, to_port, _description(payload, context))
    rule.update({"peer_type": "security_group", "peer_id": group_id})

    account_id = _optional_string(payload, "UserId", context)
    if account_id is not None:
        if not ACCOUNT_ID_PATTERN.fullmatch(account_id):
            raise ValueError(f"{context} UserId must be a 12-digit AWS account ID.")
        rule["peer_account_id"] = account_id
    vpc_id = _optional_string(payload, "VpcId", context)
    if vpc_id is not None:
        rule["peer_vpc_id"] = _validated_id(vpc_id, VPC_ID_PATTERN, context)
    peering_status = _optional_string(payload, "PeeringStatus", context)
    if peering_status is not None:
        rule["peering_status"] = peering_status
    group_name = _optional_string(payload, "GroupName", context)
    if group_name is not None:
        rule["peer_group_name"] = group_name
    peering_connection_id = _optional_string(payload, "VpcPeeringConnectionId", context)
    if peering_connection_id is not None:
        rule["peer_vpc_peering_connection_id"] = _validated_id(
            peering_connection_id,
            VPC_PEERING_CONNECTION_ID_PATTERN,
            context,
        )
    return rule


def _permission_rules(
    permission: dict[str, Any],
    context: str,
) -> tuple[list[dict[str, Any]], set[str]]:
    protocol, from_port, to_port = _normalized_ports(permission, context)
    rules: list[dict[str, Any]] = []
    peer_types: set[str] = set()

    for index, target in enumerate(_object_list(permission, "IpRanges", context)):
        rules.append(
            _cidr_rule(
                target,
                cidr_key="CidrIp",
                version=4,
                context=f"{context} IPv4 range {index + 1}",
                protocol=protocol,
                from_port=from_port,
                to_port=to_port,
            )
        )
    for index, target in enumerate(_object_list(permission, "Ipv6Ranges", context)):
        rules.append(
            _cidr_rule(
                target,
                cidr_key="CidrIpv6",
                version=6,
                context=f"{context} IPv6 range {index + 1}",
                protocol=protocol,
                from_port=from_port,
                to_port=to_port,
            )
        )
    for index, target in enumerate(_object_list(permission, "PrefixListIds", context)):
        rules.append(
            _prefix_list_rule(
                target,
                context=f"{context} prefix list {index + 1}",
                protocol=protocol,
                from_port=from_port,
                to_port=to_port,
            )
        )
        peer_types.add("prefix-list")
    for index, target in enumerate(_object_list(permission, "UserIdGroupPairs", context)):
        rules.append(
            _security_group_rule(
                target,
                context=f"{context} security-group reference {index + 1}",
                protocol=protocol,
                from_port=from_port,
                to_port=to_port,
            )
        )
        peer_types.add("security-group")

    if not rules:
        raise ValueError(f"{context} has no CIDR, prefix-list, or security-group target.")
    return rules, peer_types


def _tags(group: dict[str, Any], context: str) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for index, tag in enumerate(_object_list(group, "Tags", context)):
        tag_context = f"{context} tag {index + 1}"
        key = _required_string(tag, "Key", tag_context)
        value = tag.get("Value")
        if not isinstance(value, str):
            raise ValueError(f"{tag_context} Value must be a string.")
        if key in normalized:
            raise ValueError(f"{context} contains duplicate tag key {key}.")
        normalized[key] = value
    return normalized


def _normalized_group(group: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
    group_id = _validated_id(
        _required_string(group, "GroupId", "Security group"),
        SECURITY_GROUP_ID_PATTERN,
        "Security group",
    )
    context = f"Security group {group_id}"
    owner_id = _required_string(group, "OwnerId", context)
    if not ACCOUNT_ID_PATTERN.fullmatch(owner_id):
        raise ValueError(f"{context} OwnerId must be a 12-digit AWS account ID.")
    vpc_id = _validated_id(
        _required_string(group, "VpcId", context),
        VPC_ID_PATTERN,
        context,
    )

    peer_types: set[str] = set()
    inbound_rules: list[dict[str, Any]] = []
    for index, permission in enumerate(_object_list(group, "IpPermissions", context, required=True)):
        rules, discovered = _permission_rules(permission, f"{context} inbound permission {index + 1}")
        inbound_rules.extend(rules)
        peer_types.update(discovered)
    outbound_rules: list[dict[str, Any]] = []
    for index, permission in enumerate(
        _object_list(group, "IpPermissionsEgress", context, required=True)
    ):
        rules, discovered = _permission_rules(permission, f"{context} outbound permission {index + 1}")
        outbound_rules.extend(rules)
        peer_types.update(discovered)

    normalized: dict[str, Any] = {
        "id": group_id,
        "name": _required_string(group, "GroupName", context),
        "description": _required_string(group, "Description", context),
        "owner_id": owner_id,
        "vpc_id": vpc_id,
        "tags": _tags(group, context),
        "inbound_rules": inbound_rules,
        "outbound_rules": outbound_rules,
    }
    arn = _optional_string(group, "SecurityGroupArn", context)
    if arn is not None:
        match = SECURITY_GROUP_ARN_PATTERN.fullmatch(arn)
        if match is None:
            raise ValueError(f"{context} SecurityGroupArn is not a valid EC2 security group ARN.")
        if match.group(1) != owner_id or match.group(2) != group_id:
            raise ValueError(
                f"{context} SecurityGroupArn does not match its OwnerId and GroupId."
            )
        normalized["arn"] = arn
    return normalized, peer_types


def normalize_aws_ec2_environment(response: dict[str, Any]) -> Ec2NormalizationResult:
    """Convert a complete DescribeSecurityGroups response into network analyzer input."""

    if "NextToken" in response and response["NextToken"] is not None:
        next_token = response["NextToken"]
        if not isinstance(next_token, str) or not next_token:
            raise ValueError("DescribeSecurityGroups NextToken must be a non-empty string or null.")
        raise ValueError(
            "DescribeSecurityGroups response is paginated; collect all pages before analysis."
        )
    groups = _object_list(response, "SecurityGroups", "DescribeSecurityGroups", required=True)
    if not groups:
        raise ValueError("DescribeSecurityGroups response must contain at least one security group.")

    normalized_groups: list[dict[str, Any]] = []
    seen_group_ids: set[str] = set()
    account_ids: set[str] = set()
    warnings: list[str] = []
    for group in groups:
        normalized, peer_types = _normalized_group(group)
        group_id = normalized["id"]
        if group_id in seen_group_ids:
            raise ValueError(f"DescribeSecurityGroups contains duplicate security group {group_id}.")
        seen_group_ids.add(group_id)
        account_ids.add(normalized["owner_id"])
        normalized_groups.append(normalized)
        for peer_type in sorted(peer_types):
            warnings.append(
                f"Security group {group_id} contains {peer_type} targets; they were preserved "
                "but are not evaluated for public CIDR exposure."
            )

    if len(account_ids) != 1:
        raise ValueError(
            "DescribeSecurityGroups response contains multiple owner account IDs; "
            "analyze one account snapshot at a time."
        )
    return Ec2NormalizationResult(
        environment={
            "account_id": next(iter(account_ids)),
            "security_groups": normalized_groups,
        },
        warnings=tuple(warnings),
    )


def load_aws_ec2_environment(path: Path) -> Ec2NormalizationResult:
    """Load and normalize a complete native DescribeSecurityGroups response."""

    return normalize_aws_ec2_environment(_load_json_object(path))
