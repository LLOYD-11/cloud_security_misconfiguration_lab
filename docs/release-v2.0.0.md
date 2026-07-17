# Version 2.0.0

Released: 2026-07-17

Version 2 turns the original four-module student lab into a reproducible,
installable, and evidence-aware cloud security analysis project while
preserving its offline safety boundary.

## Highlights

- Native AWS evidence adapters for IAM authorization details and credential
  reports, S3 security evidence bundles, EC2 security groups, and CloudTrail
  JSON or gzip records
- Deeper IAM, storage, network, and CloudTrail detection across 35 cataloged
  rules
- Coverage summaries that separate evidence completeness from finding count
- Deterministic CloudTrail incident correlation with explicit confidence
- A versioned rule catalog with qualified AWS Security Hub CSPM, CIS AWS
  Foundations, and MITRE ATT&CK mappings
- Explainable P0-P3 remediation planning
- An evidence-based attack timeline with omissions and richer incident context
- A unified installable CLI with retained legacy analyzer entry points
- Python 3.10 and 3.13 CI, strict typing, linting, branch coverage, deterministic
  artifact checks, and wheel/sdist verification

## Deterministic Demo

The bundled pipeline produces:

| Artifact | Result |
| --- | ---: |
| Findings | 39 |
| Built-in rules | 35 |
| Analysis summaries | 4 |
| Correlated incidents | 2 |
| Remediation actions | 36 |
| Timeline entries | 11 |
| Timeline omissions | 0 |

Run it with:

```bash
python3 -m cloud_security_lab demo --report-date 2026-06-30
```

The generated report must match
[`reports/cloud_security_report_sample.md`](../reports/cloud_security_report_sample.md)
byte-for-byte.

## Upgrade Notes

- Python 3.10 or later is required.
- The runtime has no third-party package dependencies.
- The preferred interface is `cloud-security-lab` or
  `python -m cloud_security_lab`.
- Original IAM, storage, network, CloudTrail, and report scripts remain
  supported.
- Shared finding inputs now require the versioned object written by the
  analyzers. Unversioned finding lists are rejected.
- Native CloudTrail can accept multiple JSON or JSON.GZ files in one run.
- Result-affecting dates and windows are represented explicitly for
  reproducibility.

## Evidence Boundary

Version 2 remains an offline analysis lab:

- It does not authenticate to AWS or change resources.
- It does not calculate complete IAM effective permissions.
- It does not prove network reachability without supplied context.
- It does not verify CloudTrail log integrity or perform behavioral baselining.
- Incidents, priorities, and timeline narratives support triage; they do not
  prove compromise, causation, or business impact.

See [Architecture](architecture.md), [Design decisions](design-decisions.md),
and [Known limitations](known-limitations.md) for the complete boundaries.

## Verification

The release gate includes:

- 268 unit, regression, compatibility, and contract tests
- 94% project branch coverage
- 99% branch coverage for the attack-timeline module
- Ruff linting and strict production mypy checks
- Draft 2020-12 validation for committed and generated artifacts
- Byte-for-byte report and rule-catalog regeneration
- Native IAM, S3, EC2, and CloudTrail pipeline checks
- Wheel and source-distribution builds
- A clean-environment demo installed from the built wheel
- Tag-to-package version verification before GitHub Release creation

GitHub Actions runs the complete gate on Python 3.10 and 3.13.

## Documentation

- [Architecture](architecture.md)
- [Design decisions](design-decisions.md)
- [Data contracts](data-contracts.md)
- [Native AWS inputs](native-aws-inputs.md)
- [Rule catalog](rule-catalog.md)
- [Analysis coverage](analysis-coverage.md)
- [Incident correlation](incident-correlation.md)
- [Remediation prioritization](remediation-prioritization.md)
- [Attack timeline](attack-timeline.md)
- [Known limitations](known-limitations.md)
