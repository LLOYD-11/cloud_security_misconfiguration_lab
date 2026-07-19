"""Analyze offline security group data for risky network exposure."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from datetime import datetime
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
from cloud_inputs import load_simplified_environment
from cloud_rules import validate_rule_emission

REF_AWS_SECURITY_GROUPS = "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"
REF_AWS_SECURITY_GROUP_RULES = "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html"
REF_AWS_SECURITY_GROUP_USE_CASES = (
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html"
)
REF_AWS_REACHABILITY_ANALYZER = (
    "https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html"
)
REF_MITRE_CLOUD_COMPUTE_INFRA_MODIFY = "https://attack.mitre.org/techniques/T1578/005/"
REF_DOCKER_REMOTE_ACCESS = "https://docs.docker.com/engine/daemon/remote-access/"
REF_ELASTIC_NETWORKING = (
    "https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html"
)
REF_KUBERNETES_PORTS = "https://kubernetes.io/docs/reference/networking/ports-and-protocols/"
REF_MICROSOFT_SERVICE_PORTS = (
    "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/"
    "service-overview-and-network-port-requirements"
)
REF_MICROSOFT_WINRM = (
    "https://learn.microsoft.com/en-us/windows/win32/winrm/"
    "installation-and-configuration-for-windows-remote-management"
)
REF_MONGODB_PORTS = "https://www.mongodb.com/docs/manual/reference/default-mongodb-port/"
REF_REDIS_SECURITY = "https://redis.io/docs/latest/operate/oss_and_stack/management/security/"


@dataclass(frozen=True)
class ServiceDefinition:
    """A sensitive service endpoint and its default exposure risk."""

    port: int
    name: str
    protocols: frozenset[str]
    severity: str
    category: str
    reference: str


@dataclass(frozen=True)
class ReachabilityAssessment:
    """Direction-specific path evidence supplied outside security-group rules."""

    status: str
    method: str = ""
    observed_at: str = ""
    scope: str = ""
    evidence: tuple[str, ...] = ()
    resource_ids: tuple[str, ...] = ()


SERVICE_CATALOG = (
    ServiceDefinition(
        22,
        "SSH",
        frozenset({"tcp"}),
        "high",
        "remote-administration",
        REF_AWS_SECURITY_GROUP_USE_CASES,
    ),
    ServiceDefinition(
        445,
        "SMB",
        frozenset({"tcp"}),
        "high",
        "remote-administration",
        REF_MICROSOFT_SERVICE_PORTS,
    ),
    ServiceDefinition(
        1433,
        "Microsoft SQL Server",
        frozenset({"tcp"}),
        "high",
        "database",
        REF_AWS_SECURITY_GROUP_USE_CASES,
    ),
    ServiceDefinition(
        1521,
        "Oracle Database",
        frozenset({"tcp"}),
        "high",
        "database",
        REF_AWS_SECURITY_GROUP_USE_CASES,
    ),
    ServiceDefinition(
        2375,
        "Docker API without TLS",
        frozenset({"tcp"}),
        "critical",
        "control-plane",
        REF_DOCKER_REMOTE_ACCESS,
    ),
    ServiceDefinition(
        2376,
        "Docker API with TLS",
        frozenset({"tcp"}),
        "high",
        "control-plane",
        REF_DOCKER_REMOTE_ACCESS,
    ),
    ServiceDefinition(
        2379,
        "etcd client API",
        frozenset({"tcp"}),
        "critical",
        "control-plane",
        REF_KUBERNETES_PORTS,
    ),
    ServiceDefinition(
        2380,
        "etcd peer API",
        frozenset({"tcp"}),
        "critical",
        "control-plane",
        REF_KUBERNETES_PORTS,
    ),
    ServiceDefinition(
        3306,
        "MySQL/Aurora",
        frozenset({"tcp"}),
        "high",
        "database",
        REF_AWS_SECURITY_GROUP_USE_CASES,
    ),
    ServiceDefinition(
        3389,
        "RDP",
        frozenset({"tcp", "udp"}),
        "high",
        "remote-administration",
        REF_AWS_SECURITY_GROUP_USE_CASES,
    ),
    ServiceDefinition(
        5432,
        "PostgreSQL",
        frozenset({"tcp"}),
        "high",
        "database",
        REF_AWS_SECURITY_GROUP_USE_CASES,
    ),
    ServiceDefinition(
        5439,
        "Amazon Redshift",
        frozenset({"tcp"}),
        "high",
        "database",
        REF_AWS_SECURITY_GROUP_USE_CASES,
    ),
    ServiceDefinition(
        5985,
        "WinRM over HTTP",
        frozenset({"tcp"}),
        "high",
        "remote-administration",
        REF_MICROSOFT_WINRM,
    ),
    ServiceDefinition(
        5986,
        "WinRM over HTTPS",
        frozenset({"tcp"}),
        "high",
        "remote-administration",
        REF_MICROSOFT_WINRM,
    ),
    ServiceDefinition(
        6379,
        "Redis",
        frozenset({"tcp"}),
        "critical",
        "data-service",
        REF_REDIS_SECURITY,
    ),
    ServiceDefinition(
        6443,
        "Kubernetes API server",
        frozenset({"tcp"}),
        "high",
        "control-plane",
        REF_KUBERNETES_PORTS,
    ),
    ServiceDefinition(
        9200,
        "Elasticsearch HTTP API",
        frozenset({"tcp"}),
        "high",
        "data-service",
        REF_ELASTIC_NETWORKING,
    ),
    ServiceDefinition(
        9300,
        "Elasticsearch transport API",
        frozenset({"tcp"}),
        "high",
        "data-service",
        REF_ELASTIC_NETWORKING,
    ),
    ServiceDefinition(
        10250,
        "Kubelet API",
        frozenset({"tcp"}),
        "high",
        "control-plane",
        REF_KUBERNETES_PORTS,
    ),
    ServiceDefinition(
        27017,
        "MongoDB",
        frozenset({"tcp"}),
        "high",
        "database",
        REF_MONGODB_PORTS,
    ),
)

SERVICE_IMPACTS = {
    "control-plane": (
        "Unauthorized callers can reach privileged orchestration or host operations through "
        "the exposed control-plane endpoint."
    ),
    "data-service": (
        "Unauthorized callers can access stored data or administrative operations through the "
        "exposed data-service endpoint."
    ),
    "database": (
        "The exposed database endpoint increases the risk of credential attacks, exploitation, "
        "or unauthorized data access."
    ),
    "remote-administration": (
        "The exposed remote-administration endpoint increases the risk of credential attacks "
        "and unauthorized host access."
    ),
}

SERVICE_REMEDIATIONS = {
    "control-plane": (
        "Place the endpoint on a private management network, require strong authentication and "
        "encryption, and allow only specific administrative sources."
    ),
    "data-service": (
        "Keep the service on private subnets, require authentication and encryption, and allow "
        "only the application security groups or trusted source ranges that need access."
    ),
    "database": (
        "Keep the database on private subnets and allow only the application security groups or "
        "trusted source ranges that require access."
    ),
    "remote-administration": (
        "Restrict administration to a VPN, bastion host, private management network, or specific "
        "trusted source addresses."
    ),
}

REACHABILITY_STATUSES = frozenset({"reachable", "not_reachable", "inconclusive"})
REACHABILITY_METHODS = frozenset(
    {
        "aws-network-access-analyzer",
        "aws-reachability-analyzer",
        "manual-topology-review",
        "other",
    }
)
DEESCALATED_SEVERITIES = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "info",
    "info": "info",
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


def _reachability_assessment(
    group: dict[str, Any],
    direction: str,
) -> ReachabilityAssessment:
    context = group.get("reachability")
    if not isinstance(context, dict):
        return ReachabilityAssessment(status="not_assessed")

    method = context.get("method")
    observed_at = context.get("observed_at")
    direction_context = context.get(direction)
    if (
        not isinstance(method, str)
        or method not in REACHABILITY_METHODS
        or not isinstance(observed_at, str)
        or not _is_offset_timestamp(observed_at)
        or not isinstance(direction_context, dict)
    ):
        return ReachabilityAssessment(status="inconclusive")

    status = direction_context.get("status")
    scope = direction_context.get("scope")
    evidence = direction_context.get("evidence")
    resource_ids = direction_context.get("resource_ids", [])
    if (
        status not in REACHABILITY_STATUSES
        or not isinstance(scope, str)
        or not scope
        or not isinstance(evidence, list)
        or not evidence
        or not all(isinstance(item, str) and item for item in evidence)
        or not isinstance(resource_ids, list)
        or not all(isinstance(item, str) and item for item in resource_ids)
    ):
        return ReachabilityAssessment(
            status="inconclusive",
            method=method,
            observed_at=observed_at,
        )

    return ReachabilityAssessment(
        status=status,
        method=method,
        observed_at=observed_at,
        scope=scope,
        evidence=tuple(evidence),
        resource_ids=tuple(resource_ids),
    )


def _is_offset_timestamp(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _reachability_metadata(
    assessment: ReachabilityAssessment,
    direction: str,
) -> dict[str, str]:
    metadata = {
        "reachability_direction": direction,
        "reachability_status": assessment.status,
    }
    if assessment.method:
        metadata["reachability_method"] = assessment.method
    if assessment.observed_at:
        metadata["reachability_observed_at"] = assessment.observed_at
    if assessment.scope:
        metadata["reachability_scope"] = assessment.scope
    if assessment.evidence:
        metadata["reachability_evidence"] = " | ".join(assessment.evidence)
    if assessment.resource_ids:
        metadata["reachability_resource_ids"] = ", ".join(assessment.resource_ids)
    return metadata


def _reachability_evidence(assessment: ReachabilityAssessment, direction: str) -> str:
    if assessment.status == "not_assessed":
        return (
            "No reachability assessment was supplied; the finding represents a permitted "
            "security-group path, not proof of end-to-end connectivity."
        )
    if assessment.status == "inconclusive":
        details = (
            f": {' | '.join(assessment.evidence).rstrip('.')}"
            if assessment.evidence
            else ""
        )
        scope = (
            f" for scope '{assessment.scope.rstrip('.')}'"
            if assessment.scope
            else ""
        )
        return (
            f"The supplied {direction} reachability assessment was inconclusive"
            f"{scope}{details}."
        )

    label = "reachable" if assessment.status == "reachable" else "not reachable"
    details = " | ".join(assessment.evidence).rstrip(".")
    return (
        f"Supplied {assessment.method} context observed at {assessment.observed_at} reports "
        f"the {direction} path as {label} for scope "
        f"'{assessment.scope.rstrip('.')}': {details}."
    )


def _contextual_severity(
    severity: str,
    assessment: ReachabilityAssessment,
) -> str:
    if assessment.status == "not_reachable":
        return DEESCALATED_SEVERITIES[severity]
    return severity


def _contextual_impact(
    impact: str,
    assessment: ReachabilityAssessment,
) -> str:
    if assessment.status == "reachable":
        return f"The supplied context reports an active end-to-end path. {impact}"
    if assessment.status == "not_reachable":
        return (
            "The supplied context reports no current end-to-end path, reducing immediate "
            "exposure. The permissive rule remains a latent risk if attachments, addresses, "
            "routes, or intermediary controls change."
        )
    if assessment.status == "inconclusive":
        return (
            f"End-to-end reachability remains inconclusive. If a public path exists, {impact[0].lower()}"
            f"{impact[1:]}"
        )
    return (
        f"End-to-end reachability was not assessed. If a public path exists, {impact[0].lower()}"
        f"{impact[1:]}"
    )


def _contextual_title(
    *,
    reachable: str,
    not_reachable: str,
    unverified: str,
    assessment: ReachabilityAssessment,
) -> str:
    if assessment.status == "reachable":
        return reachable
    if assessment.status == "not_reachable":
        return not_reachable
    return unverified


def _references(*references: str) -> list[str]:
    return list(dict.fromkeys(references))


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
    rule = validate_rule_emission(rule_id, "network", severity)
    assert rule is not None
    metadata_values = metadata or {}
    direction = metadata_values.get("direction", "unknown-direction")
    rule_index = metadata_values.get("rule_index", "unknown-rule")
    service = metadata_values.get("service")
    evidence_id = f"{resource_id}:{direction}:{rule_index}"
    if service:
        evidence_id += f":{service}"
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
            metadata=metadata_values,
            confidence=rule.confidence,
            evidence_references=[
                EvidenceReference(
                    type="ec2-security-group-rule",
                    id=evidence_id,
                )
            ],
        )
    )


def analyze_security_group(group: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    group_id = str(group.get("id", group.get("name", "unknown-security-group")))
    group_metadata = _group_metadata(group, group_id)
    ingress_reachability = _reachability_assessment(group, "ingress")

    for index, rule in enumerate(group.get("inbound_rules", [])):
        exposure_scope = _exposure_scope(rule)
        if exposure_scope is None:
            continue

        if _is_all_ports(rule):
            _add_finding(
                findings,
                severity=_contextual_severity("critical", ingress_reachability),
                rule_id="NET-002",
                resource_id=group_id,
                title=_contextual_title(
                    reachable=(
                        "All inbound ports are allowed on a reported internet-reachable path"
                    ),
                    not_reachable=(
                        "All inbound ports permit public sources without a reported reachable path"
                    ),
                    unverified="All inbound ports permit traffic from a public network",
                    assessment=ingress_reachability,
                ),
                evidence=(
                    f"Inbound rule {index + 1} allows {_rule_summary(rule)}. "
                    f"{_reachability_evidence(ingress_reachability, 'ingress')}"
                ),
                impact=_contextual_impact(
                    "Any service attached to this security group may be reachable from the "
                    "public internet.",
                    ingress_reachability,
                ),
                remediation=(
                    "Remove all-port public inbound access and allow only required ports from "
                    "trusted CIDR ranges. Reassess the end-to-end path after remediation."
                ),
                references=_references(
                    REF_AWS_SECURITY_GROUPS,
                    REF_AWS_SECURITY_GROUP_RULES,
                    REF_AWS_REACHABILITY_ANALYZER,
                    REF_MITRE_CLOUD_COMPUTE_INFRA_MODIFY,
                ),
                metadata={
                    **group_metadata,
                    "direction": "ingress",
                    "rule_index": str(index + 1),
                    "exposure_scope": exposure_scope,
                    **_reachability_metadata(ingress_reachability, "ingress"),
                },
            )
            continue

        protocol = _normalized_protocol(rule)
        for service in SERVICE_CATALOG:
            if protocol in service.protocols and _covers_port(rule, service.port):
                exposure_title = (
                    "the internet"
                    if exposure_scope == "internet-wide"
                    else "a broad public network"
                )
                _add_finding(
                    findings,
                    severity=_contextual_severity(
                        service.severity,
                        ingress_reachability,
                    ),
                    rule_id="NET-001",
                    resource_id=group_id,
                    title=_contextual_title(
                        reachable=(
                            f"Sensitive {service.name} port is allowed on a reported "
                            "internet-reachable path"
                        ),
                        not_reachable=(
                            f"Sensitive {service.name} port permits public sources without a "
                            "reported reachable path"
                        ),
                        unverified=(
                            f"Sensitive {service.name} port permits traffic from {exposure_title}"
                        ),
                        assessment=ingress_reachability,
                    ),
                    evidence=(
                        f"Inbound rule {index + 1} allows {_rule_summary(rule)}. "
                        f"{_reachability_evidence(ingress_reachability, 'ingress')}"
                    ),
                    impact=_contextual_impact(
                        SERVICE_IMPACTS[service.category],
                        ingress_reachability,
                    ),
                    remediation=(
                        f"{SERVICE_REMEDIATIONS[service.category]} Reassess the end-to-end path "
                        "after remediation."
                    ),
                    references=_references(
                        REF_AWS_SECURITY_GROUPS,
                        REF_AWS_SECURITY_GROUP_RULES,
                        REF_AWS_REACHABILITY_ANALYZER,
                        service.reference,
                    ),
                    metadata={
                        **group_metadata,
                        "direction": "ingress",
                        "rule_index": str(index + 1),
                        "port": str(service.port),
                        "protocol": protocol,
                        "service": service.name,
                        "service_category": service.category,
                        "service_default_severity": service.severity,
                        "exposure_scope": exposure_scope,
                        **_reachability_metadata(ingress_reachability, "ingress"),
                    },
                )

    egress_reachability = _reachability_assessment(group, "egress")
    for index, rule in enumerate(group.get("outbound_rules", [])):
        exposure_scope = _exposure_scope(rule)
        if exposure_scope is not None and _is_all_ports(rule):
            _add_finding(
                findings,
                severity=_contextual_severity("medium", egress_reachability),
                rule_id="NET-003",
                resource_id=group_id,
                title=_contextual_title(
                    reachable=(
                        "Unrestricted outbound traffic is allowed on a reported internet path"
                    ),
                    not_reachable=(
                        "Unrestricted outbound traffic is configured without a reported "
                        "reachable path"
                    ),
                    unverified="Security group permits unrestricted outbound traffic",
                    assessment=egress_reachability,
                ),
                evidence=(
                    f"Outbound rule {index + 1} allows {_rule_summary(rule)}. "
                    f"{_reachability_evidence(egress_reachability, 'egress')}"
                ),
                impact=_contextual_impact(
                    "Compromised workloads may communicate freely with internet destinations, "
                    "making exfiltration or command-and-control traffic harder to contain.",
                    egress_reachability,
                ),
                remediation=(
                    "Restrict outbound traffic to required protocols, ports, and destination "
                    "CIDR ranges where practical. Reassess the end-to-end path after remediation."
                ),
                references=_references(
                    REF_AWS_SECURITY_GROUPS,
                    REF_AWS_SECURITY_GROUP_RULES,
                    REF_AWS_REACHABILITY_ANALYZER,
                ),
                metadata={
                    **group_metadata,
                    "direction": "egress",
                    "rule_index": str(index + 1),
                    "exposure_scope": exposure_scope,
                    **_reachability_metadata(egress_reachability, "egress"),
                },
            )

    return with_findings_context(
        findings,
        account_id=str(group.get("owner_id") or "unknown"),
        region=str(group.get("region") or "unknown"),
        observed_at=ingress_reachability.observed_at
        or egress_reachability.observed_at
        or None,
    )


def analyze_environment(environment: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for group in environment.get("security_groups", []):
        findings.extend(analyze_security_group(group))
    return sort_findings(
        with_findings_context(
            findings,
            account_id=str(environment.get("account_id") or "unknown"),
            region=str(environment.get("region") or "unknown"),
        )
    )


def load_environment(path: Path) -> dict[str, Any]:
    return load_simplified_environment(path, "network")


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
