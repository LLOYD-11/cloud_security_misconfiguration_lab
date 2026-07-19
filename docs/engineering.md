# Engineering Checks

The project keeps runtime analysis dependency-free while providing an optional development toolchain for repeatable verification.

## Local Setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

## Release Gate

Run these commands from the repository root:

```bash
mkdir -p reports/generated
.venv/bin/ruff check .
.venv/bin/mypy cloud_analysis cloud_benchmarks cloud_security_lab cloud_findings cloud_inputs cloud_incidents cloud_remediation cloud_rules cloud_timeline iam_analyzer storage_analyzer network_analyzer cloudtrail_detector report_generator
.venv/bin/coverage run -m unittest discover
.venv/bin/coverage report
.venv/bin/coverage json -o reports/generated/coverage.json
.venv/bin/python -m cloud_benchmarks.coverage_gate reports/generated/coverage.json
.venv/bin/python -m cloud_benchmarks.runner
.venv/bin/python -m cloud_security_lab demo --report-date 2026-06-30
cmp reports/cloud_security_report_sample.md reports/generated/cloud_security_report.md
.venv/bin/python -m cloud_security_lab catalog --output reports/generated/rule_catalog.md
cmp docs/rule-catalog.md reports/generated/rule_catalog.md
.venv/bin/python -m build
```

Coverage uses branch measurement and independently fails below 90% statement
coverage or 85% branch coverage. Contract tests validate
all committed sample files, findings v2 output, generated remediation plans,
attack timelines, the canonical rule catalog, and the AWS fixture manifest
against Draft 2020-12 schemas. The manifest test also enforces exact fixture
inventory and SHA-256 integrity. AST-based completeness tests compare every
analyzer's literal rule IDs with the catalog, while timeline tests require a
classification for every CloudTrail rule. Compatibility tests call every
original module CLI so the unified package does not silently break earlier
workflows. CloudTrail tests additionally compare the optimized API-failure
window against a frozen quadratic oracle over a deterministic scaled corpus and
enforce a structural timestamp-operation bound. This proves output equivalence
and pointer monotonicity without an unstable wall-clock gate; see
[CloudTrail failure-window performance](detection-performance.md).

The benchmark runner executes 78 committed positive, boundary, hardened
negative, and malformed cases plus eight small and large scale profiles. CI
requires exact findings, exact malformed-input errors, deterministic repeated
analysis, bounded finding amplification, and calibrated peak-memory ceilings.
Elapsed time is measured and reported but is deliberately not gated. See
[Benchmarking and resilience](benchmarking.md) for the manifest, methodology,
reference measurements, and separate coverage evidence.

## Continuous Integration

GitHub Actions runs the same lint, type, test, independent coverage, benchmark,
and end-to-end checks on Python 3.10, 3.12, and 3.13. The Python 3.13 job also
builds the wheel and source distribution. Workflow permissions are limited to
read-only repository contents.

The deterministic end-to-end check fixes the report date to the sample event
date and compares the generated Markdown, including finding provenance, the
prioritized work queue, and attack timeline, byte-for-byte with the committed
report. A second byte-for-byte check regenerates the human-readable rule catalog
from its packaged JSON source. The build gate also confirms that the wheel
contains the simplified-input validator, rule catalog, remediation and timeline
modules, their schemas, and the AWS fixture manifest. It also verifies the
packaged benchmark manifest, runner, and both benchmark schemas.

## Release Process

1. Set `cloud_security_lab.__version__`, close the changelog section, complete
   the roadmap milestone, and add `docs/release-vX.Y.Z.md`.
2. Run the complete local release gate and install the wheel into a clean
   environment for one deterministic demo.
3. Commit and push the release candidate branch, then require all three Python
   matrix jobs to pass.
4. Fast-forward `main` to the verified commit and require the main-branch CI run
   to pass.
5. Create and push an annotated `vX.Y.Z` tag.

The tag starts `.github/workflows/release.yml`. That workflow verifies the tag
against the installed package version, requires the matching release-notes
file, repeats the full quality and deterministic gates, builds the wheel and
source distribution, runs the installed-wheel demo, and then creates a GitHub
Release with both distributions attached. Its write permission is scoped to
repository contents.
