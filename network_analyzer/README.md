# Network Configuration Analyzer

This module analyzes offline security group data for risky network exposure patterns.

It does not call AWS APIs or require cloud credentials. The sample data models security group rules commonly reviewed in cloud configuration assessments.

## Detection Rules

| Rule | Severity | Description |
| --- | --- | --- |
| `NET-001` | High | Protocol-aware sensitive port is open to an internet-wide or broad public CIDR |
| `NET-002` | Critical | All inbound ports are open to an internet-wide or broad public CIDR |
| `NET-003` | Medium | All outbound traffic is allowed to an internet-wide or broad public CIDR |

Sensitive ports currently include:

- `22` SSH
- `3389` RDP
- `3306` MySQL
- `5432` PostgreSQL

Each finding uses the shared schema and includes AWS security group documentation references where applicable.

Internet-wide CIDRs use the `internet-wide` exposure scope. Exceptionally broad public networks use `broad-public`. Private, loopback, link-local, and narrower allowlisted networks are not classified as broad exposure by this module.

## Run

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

The exported JSON can be passed directly to `report_generator/generate_report.py`.

## Test

```bash
python3 -m unittest network_analyzer.test_analyzer
```
