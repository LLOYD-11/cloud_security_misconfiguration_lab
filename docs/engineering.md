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
.venv/bin/ruff check .
.venv/bin/mypy cloud_security_lab cloud_findings iam_analyzer storage_analyzer network_analyzer cloudtrail_detector report_generator
.venv/bin/coverage run -m unittest discover
.venv/bin/coverage report
.venv/bin/python -m cloud_security_lab demo --report-date 2026-06-30
cmp reports/cloud_security_report_sample.md reports/generated/cloud_security_report.md
.venv/bin/python -m build
```

Coverage uses branch measurement and fails below 85%. Contract tests validate all committed sample files against Draft 2020-12 schemas. Compatibility tests call every original module CLI so the unified package does not silently break earlier workflows.

## Continuous Integration

GitHub Actions runs the same lint, type, test, coverage, and end-to-end checks on Python 3.10 and 3.13. The Python 3.13 job also builds the wheel and source distribution. Workflow permissions are limited to read-only repository contents.

The deterministic end-to-end check fixes the report date to the sample event date and compares the generated Markdown byte-for-byte with the committed report.
