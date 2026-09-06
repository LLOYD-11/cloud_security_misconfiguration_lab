# One-Page Application Summary

## Cloud Security Misconfiguration Lab

- **Category:** Cloud security engineering, evidence analysis, secure software
  design, and reproducible evaluation
- **Repository:**
  [LLOYD-11/cloud_security_misconfiguration_lab](https://github.com/LLOYD-11/cloud_security_misconfiguration_lab)
- **Public release:**
  [`v2.2.1`](https://github.com/LLOYD-11/cloud_security_misconfiguration_lab/releases/tag/v2.2.1)
- **Role:** Project direction, scope and safety decisions, evidence policy,
  quality acceptance, and release responsibility in an AI-assisted workflow

## Project Question

Can exported AWS evidence be analyzed offline through an explainable,
deterministic pipeline while keeping every result bounded by inspectable input,
explicit contracts, and reproducible evaluation?

## What The Project Implements

I directed the development of a Python lab that normalizes simplified and
native AWS-shaped IAM, S3, EC2 security-group, and CloudTrail evidence. Its 35
cataloged rules produce a shared finding format, coverage summaries, correlated
incidents, prioritized remediation, a chronological timeline, and a combined
Markdown report. The analyzer runtime does not authenticate to AWS, modify
cloud resources, or require third-party packages.

The main architectural decision was to place validation and normalization at
the evidence boundary while keeping detection and presentation independent.
This made incomplete evidence, provenance, rule confidence, report integrity,
and deterministic identity visible instead of burying them inside scanner
output.

## Evidence Snapshot

| Area | Published Evidence |
| --- | --- |
| Deterministic sample | 39 findings, 2 incidents, 36 remediation actions, and 11 timeline entries |
| Rule coverage | 35 rules across IAM, S3, EC2 security groups, and CloudTrail |
| Development assurance | Python 3.10-3.13 CI, statement and branch coverage gates, 78 exact functional cases, 4 malformed-input cases, and 8 scale profiles |
| Frozen evaluation | 32 synthetic cases, 42 evidence files, 176 assertions, and 168 scored decisions |
| Primary result | 77 TP, 2 FP, 1 FN, 90 TN, precision 0.9747, recall 0.9872, and F1 0.9809 |
| External overlap | 24/24 decisions agreed where a pinned Prowler predicate and retained evidence had exact semantic overlap |

The preregistered evaluation **did not pass** all acceptance checks. Storage
precision was `0.8824`, below the registered `0.90` threshold, and two
predictions lacked predeclared decision keys. The evaluation also exposed one
`IAM-005` false negative caused by incorrect `BoolIfExists` MFA semantics. I
preserved the frozen result and fixed the analyzer only in later development,
so the published score was not rewritten after disclosure.

## Engineering Lessons

- A zero-finding result and complete evidence are different facts.
- Native provider parsing belongs at an adapter boundary, not inside rules.
- Event identity, duplicate handling, policy operators, and output encoding
  require adversarial interaction tests.
- Development tests are regression evidence, not an unbiased accuracy study.
- A failed preregistered threshold is useful evidence when it remains visible.

## Authorship And Boundaries

This is a Lloyd-directed, AI-assisted project. OpenAI Codex materially assisted
architecture exploration, implementation, tests, debugging, evaluation-artifact
preparation, documentation, command execution, and review; a second AI reviewer
was consulted intermittently during earlier work. I selected and approved the
project scope, safety boundary, quality standard, evidence policy, and
publication decisions. AI feedback is not presented as independent human
review, and the synthetic evaluation is not third-party certification.

The current system is not a live policy engine, production scanner, complete
IAM authorization evaluator, or proof of workload reachability. A bounded
real-system demonstration has a reviewed deployment and teardown protocol, but
no live AWS result is claimed until an authorized disposable account is used
and sanitized evidence is published.

## Review Path

Start with the [sample report](../reports/cloud_security_report_sample.md), then
read the [technical case study](technical-case-study.md),
[contribution reflection](contribution-and-reflection.md), and
[research claim register](research-question.md). The
[five-minute walkthrough](demo-walkthrough.md) provides the shortest spoken
demonstration path.
