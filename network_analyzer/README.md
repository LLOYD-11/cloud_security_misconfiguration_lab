# Network Configuration Analyzer

This module analyzes offline security group data for risky network exposure patterns.

It does not call AWS APIs or require cloud credentials. It accepts the documented simplified model directly, while the unified CLI can normalize a complete native EC2 `DescribeSecurityGroups` response before analysis.

## Detection Rules

| Rule | Default Severity | Description |
| --- | --- | --- |
| `NET-001` | Critical or High by service | Protocol-aware sensitive service port permits traffic from an internet-wide or broad public CIDR |
| `NET-002` | Critical | All inbound ports permit traffic from an internet-wide or broad public CIDR |
| `NET-003` | Medium | All outbound traffic is allowed to an internet-wide or broad public CIDR |

Internet-wide CIDRs use the `internet-wide` exposure scope. Exceptionally broad public networks use `broad-public`. Private, loopback, link-local, documentation, multicast, reserved, and narrower public networks are not classified as broad exposure by this module.

An all-protocol or `0-65535` public inbound rule produces only `NET-002`; it does not duplicate every catalog service as `NET-001`.

## Sensitive Service Catalog

The catalog uses protocol and port together. Custom service ports are outside the current detector.

| Port | Protocol | Service | Category | Default Severity |
| ---: | --- | --- | --- | --- |
| 22 | TCP | SSH | Remote administration | High |
| 445 | TCP | SMB | Remote administration | High |
| 1433 | TCP | Microsoft SQL Server | Database | High |
| 1521 | TCP | Oracle Database | Database | High |
| 2375 | TCP | Docker API without TLS | Control plane | Critical |
| 2376 | TCP | Docker API with TLS | Control plane | High |
| 2379 | TCP | etcd client API | Control plane | Critical |
| 2380 | TCP | etcd peer API | Control plane | Critical |
| 3306 | TCP | MySQL/Aurora | Database | High |
| 3389 | TCP, UDP | RDP | Remote administration | High |
| 5432 | TCP | PostgreSQL | Database | High |
| 5439 | TCP | Amazon Redshift | Database | High |
| 5985 | TCP | WinRM over HTTP | Remote administration | High |
| 5986 | TCP | WinRM over HTTPS | Remote administration | High |
| 6379 | TCP | Redis | Data service | Critical |
| 6443 | TCP | Kubernetes API server | Control plane | High |
| 9200 | TCP | Elasticsearch HTTP API | Data service | High |
| 9300 | TCP | Elasticsearch transport API | Data service | High |
| 10250 | TCP | Kubelet API | Control plane | High |
| 27017 | TCP | MongoDB | Database | High |

Each service finding records the matched port, protocol, service name, category, and pre-context default severity. References point to AWS and the relevant service owner's documentation.

## Reachability Context

A security group rule is one path component; it does not by itself prove that a workload has a public address, route, network interface, load balancer path, or permissive intermediary control. Findings therefore record one of four effective states:

| Status | Meaning | Severity Behavior |
| --- | --- | --- |
| `reachable` | Supplied evidence reports an end-to-end path | Keep the rule or service default |
| `not_reachable` | Supplied evidence reports no current end-to-end path | Lower one level and retain the latent configuration risk |
| `inconclusive` | A supplied assessment could not determine the path | Keep the default |
| `not_assessed` | No usable assessment was supplied | Keep the default |

The versioned auxiliary contract is [`network-reachability-context-v1.0.schema.json`](../schemas/network-reachability-context-v1.0.schema.json). Each security-group entry includes independent ingress and egress status, a required scope statement, assessment method, observation timestamp, evidence statements, and optional resource IDs.

A direction status is applied to every analyzer finding covered by its stated scope. Mark a direction `reachable` or `not_reachable` only when the supporting work covers every relevant attachment, address family, protocol, port, and intermediary path named in that scope; otherwise use `inconclusive`. AWS Reachability Analyzer and Network Access Analyzer are currently limited to IPv4, so an AWS-derived assessment must not claim IPv6 coverage.

Supported method labels are:

- `aws-reachability-analyzer`
- `aws-network-access-analyzer`
- `manual-topology-review`
- `other`

The adapter validates and attaches the supplied conclusion. It does not parse raw AWS Reachability Analyzer or Network Access Analyzer responses, verify the stated evidence against a live account, or keep the result current after topology changes.

Native prefix-list and security-group targets are retained in normalized evidence and produce warnings. Their membership and transitive reachability are not resolved, so current detection rules evaluate CIDR targets only.

## Run

Run the compatibility entrypoint with the simplified sample, which embeds reachability context:

```bash
python3 network_analyzer/analyzer.py \
  sample_data/network/sample_network_environment.json
```

Export JSON:

```bash
python3 network_analyzer/analyzer.py \
  sample_data/network/sample_network_environment.json \
  --output reports/generated/network_findings.json
```

Analyze the bundled native EC2 response and separate context through the unified CLI:

```bash
python3 -m cloud_security_lab analyze network \
  sample_data/aws/ec2/describe_security_groups.json \
  --input-format aws \
  --reachability-context sample_data/aws/ec2/network_reachability_context.json \
  --normalized-output reports/generated/normalized_network_environment.json \
  --output reports/generated/network_findings.json
```

Omit `--reachability-context` to perform configuration-only analysis. Every resulting finding will explicitly record `reachability_status: not_assessed`.

See [`docs/native-aws-inputs.md`](../docs/native-aws-inputs.md) for collection guidance, validation behavior, and evidence boundaries.

## Test

```bash
python3 -m unittest network_analyzer.test_analyzer \
  cloud_security_lab.normalizers.test_network_context
```
