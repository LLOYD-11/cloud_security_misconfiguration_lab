# Five-Minute Demo Walkthrough

This walkthrough presents the project to an application reviewer or interviewer
without hiding its evidence boundaries. Run commands from the repository root.

## 0:00 - Frame the Problem

The lab analyzes exported AWS security evidence offline. It never authenticates
to AWS, stores credentials, or changes resources. Four analyzers share
versioned findings so detection, correlation, prioritization, and reporting
remain separate and testable.

Point to:

- [System architecture](architecture.md)
- [Known limitations](known-limitations.md)
- the zero-runtime-dependency and Python CI badges in the
  [README](../README.md)

## 0:30 - Run the Complete Pipeline

```bash
python3 -m cloud_security_lab demo --report-date 2026-06-30
```

Expected summary:

```text
IAM: 9 findings
Storage: 9 findings
Network: 10 findings
CloudTrail: 11 findings
CloudTrail incidents: 2
Prioritized remediation: 36 actions
Attack timeline: 11 entries
Combined report: 39 findings
```

The explicit date makes the report deterministic. CI regenerates it and
compares it byte-for-byte with the committed sample.

## 1:15 - Explain the Evidence Flow

1. Simplified fixtures or native IAM, S3, EC2, and CloudTrail exports enter
   module-specific normalizers.
2. Normalizers reject known truncation and incomplete collection patterns,
   then produce stable analyzer environments.
3. Analyzers emit a shared finding contract with stable identity, account,
   Region, observation time, confidence, and source references.
4. Separate engines create incidents, remediation actions, and timeline
   entries without changing the original finding evidence.

Open:

- [`cloud_findings/finding.py`](../cloud_findings/finding.py)
- [Native AWS inputs](native-aws-inputs.md)
- [Data contracts](data-contracts.md)

## 2:00 - Tell the Attack-Chain Story

Open the [sample report](../reports/cloud_security_report_sample.md) at
`Attack Timeline`.

The main synthetic sequence records `alice-admin` removing MFA, changing a
security group and bucket policy, modifying IAM access, creating a persistent
credential, changing role trust, deleting a detector, and scheduling KMS key
deletion over 19 minutes.

The correlation is critical and high-confidence because eight distinct rules
and events share the same account, actor, source, and bounded window. The report
still states that chronology does not prove malicious intent, causation, or
attribution.

## 3:00 - Explain Remediation Decisions

Open `Prioritized Remediation Plan` in the sample report.

- `P0` is immediate incident response.
- `P1` covers other incidents, critical findings, and configuration linked to
  a P0 incident.
- `P2` is urgent hardening for high findings or other incident-linked work.
- `P3` is planned hardening for remaining posture findings.

Incident response and permanent configuration work remain separate. The plan
uses published priority rules instead of an opaque numeric risk score.

## 4:00 - Show Engineering Evidence

```bash
mkdir -p reports/generated
.venv/bin/coverage run -m unittest discover
.venv/bin/coverage json -o reports/generated/coverage.json
.venv/bin/python -m cloud_benchmarks.coverage_gate \
  reports/generated/coverage.json
.venv/bin/python -m cloud_benchmarks.runner
```

Current evidence:

- 375 tests
- 95.51% statement coverage
- 89.00% branch coverage
- 78 exact functional benchmark cases
- 4 exact fail-closed malformed-input cases
- 8 deterministic scale cases up to 10,000 inputs
- Python 3.10, 3.11, 3.12, and 3.13 GitHub Actions coverage

Finish with [Benchmarking and resilience](benchmarking.md) and the
[upgrade traceability matrix](traceability.md), which map the upgrade
requirements to implementation and verification artifacts.

## 4:45 - Close with the Boundary

This project demonstrates offline cloud-security reasoning, data-contract
design, deterministic testing, and evidence-aware reporting. It is not a live
AWS policy engine, a replacement for Security Hub or IAM Access Analyzer, or
proof that an account is secure. Those limits are part of the design rather than
hidden caveats.
