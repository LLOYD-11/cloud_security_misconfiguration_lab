"""Analyze offline security group data for risky network exposure."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cloud_findings import Finding, sort_findings, write_findings

REF_AWS_SECURITY_GROUPS = "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"
REF_AWS_SECURITY_GROUP_RULES = "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
REF_MITRE_CLOUD_COMPUTE_INFRA_MODIFY = "https://attack.mitre.org/techniques/T1578/005/"

SENSITIVE_PORTS = {
    22: ("SSH", frozenset({"tcp"})),
    3389: ("RDP", frozenset({"tcp", "udp"})),
    3306: ("MySQL", frozenset({"tcp"})),
    5432: ("PostgreSQL", frozenset({"tcp"})),
}

BROAD_PUBLIC_PREFIX = {4: 8, 6: 32}
NON_PUBLIC_IPV4_NETWORKS = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)
NON_PUBLIC_IPV6_NETWORKS = tuple(
    ipaddress.IPv6Network(cidr)
    for cidr in (
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "100::/64",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


def _rule_cidr(rule: dict[str, Any]) -> str:
    return str(rule.get("cidr", rule.get("cidr_ip", rule.get("cidr_ipv6", ""))))


def _group_metadata(group: dict[str, Any], group_id: str) -> dict[str, str]:
    metadata = {"group_name": str(group.get("name", group_id))}
    for key in ("owner_id", "vpc_id"):
        value = group.get(key)
        if value:
            metadata[key] = str(value)
    return metadata


def _exposure_scope(rule: dict[str, Any]) -> str | None:
    try:
        network = ipaddress.ip_network(_rule_cidr(rule), strict=False)
    except ValueError:
        return None

    if network.prefixlen == 0:
        return "internet-wide"
    if isinstance(network, ipaddress.IPv4Network):
        if any(network.subnet_of(non_public) for non_public in NON_PUBLIC_IPV4_NETWORKS):
            return None
    elif any(network.subnet_of(non_public) for non_public in NON_PUBLIC_IPV6_NETWORKS):
        return None
    if network.prefixlen <= BROAD_PUBLIC_PREFIX[network.version]:
        return "broad-public"
    return None


def _protocol(rule: dict[str, Any]) -> str:
    return str(rule.get("protocol", "")).lower()


def _normalized_protocol(rule: dict[str, Any]) -> str:
    protocol = _protocol(rule)
    return {"6": "tcp", "17": "udp"}.get(protocol, protocol)


def _port_range(rule: dict[str, Any]) -> tuple[int | None, int | None]:
    from_port = rule.get("from_port")
    to_port = rule.get("to_port")
    if from_port is None or to_port is None:
        return None, None
    return int(from_port), int(to_port)


def _is_all_ports(rule: dict[str, Any]) -> bool:
    protocol = _protocol(rule)
    from_port, to_port = _port_range(rule)
    return protocol in {"-1", "all", "any"} or (from_port == 0 and to_port == 65535)


def _covers_port(rule: dict[str, Any], port: int) -> bool:
    if _is_all_ports(rule):
        return True
    from_port, to_port = _port_range(rule)
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port


def _rule_summary(rule: dict[str, Any]) -> str:
    protocol = _protocol(rule) or "unknown"
    from_port, to_port = _port_range(rule)
    if from_port is None or to_port is None:
        ports = "all"
    elif from_port == to_port:
        ports = str(from_port)
    else:
        ports = f"{from_port}-{to_port}"
    return f"{protocol} {ports} from {_rule_cidr(rule)}"


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
            module="network",
            category="network-exposure",
            resource_type="security_group",
            resource_id=resource_id,
            title=title,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            references=references,
            metadata=metadata or {},
        )
    )


def analyze_security_group(group: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    group_id = str(group.get("id", group.get("name", "unknown-security-group")))
    group_metadata = _group_metadata(group, group_id)

    for index, rule in enumerate(group.get("inbound_rules", [])):
        exposure_scope = _exposure_scope(rule)
        if exposure_scope is None:
            continue

        if _is_all_ports(rule):
            _add_finding(
                findings,
                severity="critical",
                rule_id="NET-002",
                resource_id=group_id,
                title="Security group allows all inbound ports from the internet",
                evidence=f"Inbound rule {index + 1} allows {_rule_summary(rule)}.",
                impact="Any exposed service attached to this security group may be reachable from the public internet.",
                remediation="Remove all-port public inbound access and allow only required ports from trusted CIDR ranges.",
                references=[REF_AWS_SECURITY_GROUPS, REF_AWS_SECURITY_GROUP_RULES, REF_MITRE_CLOUD_COMPUTE_INFRA_MODIFY],
                metadata={
                    **group_metadata,
                    "rule_index": str(index + 1),
                    "exposure_scope": exposure_scope,
                },
            )
            continue

        protocol = _normalized_protocol(rule)
        for port, (service, supported_protocols) in SENSITIVE_PORTS.items():
            if protocol in supported_protocols and _covers_port(rule, port):
                exposure_title = (
                    "the internet"
                    if exposure_scope == "internet-wide"
                    else "a broad public network"
                )
                _add_finding(
                    findings,
                    severity="high",
                    rule_id="NET-001",
                    resource_id=group_id,
                    title=f"Sensitive {service} port is open to {exposure_title}",
                    evidence=f"Inbound rule {index + 1} allows {_rule_summary(rule)}.",
                    impact=f"{service} exposure can increase the risk of brute force, exploitation, or unauthorized administrative access.",
                    remediation=f"Restrict {service} access to a VPN, bastion host, private CIDR, or specific trusted IP range.",
                    references=[REF_AWS_SECURITY_GROUPS, REF_AWS_SECURITY_GROUP_RULES],
                    metadata={
                        **group_metadata,
                        "rule_index": str(index + 1),
                        "port": str(port),
                        "service": service,
                        "exposure_scope": exposure_scope,
                    },
                )

    for index, rule in enumerate(group.get("outbound_rules", [])):
        exposure_scope = _exposure_scope(rule)
        if exposure_scope is not None and _is_all_ports(rule):
            _add_finding(
                findings,
                severity="medium",
                rule_id="NET-003",
                resource_id=group_id,
                title="Security group allows unrestricted outbound traffic",
                evidence=f"Outbound rule {index + 1} allows {_rule_summary(rule)}.",
                impact="Compromised workloads may communicate freely with internet destinations, making exfiltration or command-and-control traffic harder to contain.",
                remediation="Restrict outbound traffic to required protocols, ports, and destination CIDR ranges where practical.",
                references=[REF_AWS_SECURITY_GROUPS, REF_AWS_SECURITY_GROUP_RULES],
                metadata={
                    **group_metadata,
                    "rule_index": str(index + 1),
                    "exposure_scope": exposure_scope,
                },
            )

    return findings


def analyze_environment(environment: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for group in environment.get("security_groups", []):
        findings.extend(analyze_security_group(group))
    return sort_findings(findings)


def load_environment(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Network environment file must contain a JSON object.")
    return data


def print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("No network findings detected.")
        return

    print(f"Network findings detected: {len(findings)}")
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
        description="Analyze offline security group JSON data for network exposure risks."
    )
    parser.add_argument("input", type=Path, help="Path to the sample network environment JSON file.")
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
