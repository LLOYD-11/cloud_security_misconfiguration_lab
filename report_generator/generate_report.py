"""Generate Markdown risk reports from shared finding JSON files."""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cloud_findings import Finding, load_findings_file, sort_findings
from cloud_incidents import Incident, load_incidents_file, sort_incidents

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _parse_report_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "report date must use YYYY-MM-DD format"
        ) from exc


def load_all_findings(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        findings.extend(load_findings_file(path))
    return sort_findings(findings)


def load_all_incidents(paths: Iterable[Path]) -> list[Incident]:
    incidents: list[Incident] = []
    for path in paths:
        incidents.extend(load_incidents_file(path))
    return sort_incidents(incidents)


def _severity_counts(findings: Iterable[Finding]) -> Counter[str]:
    return Counter(finding.severity.lower() for finding in findings)


def _module_counts(findings: Iterable[Finding]) -> Counter[str]:
    return Counter(finding.module for finding in findings)


def _severity_label(severity: str) -> str:
    return severity.capitalize()


def _format_metadata(finding: Finding) -> str:
    if not finding.metadata:
        return "None"
    return ", ".join(f"{key}: {value}" for key, value in sorted(finding.metadata.items()))


def _group_by_severity(findings: Iterable[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in sort_findings(findings):
        grouped[finding.severity.lower()].append(finding)
    return grouped


def render_report(
    findings: list[Finding],
    *,
    source_files: Iterable[Path],
    report_date: date | None = None,
    incidents: Iterable[Incident] = (),
) -> str:
    report_date = report_date or date.today()
    sorted_items = sort_findings(findings)
    severity_counts = _severity_counts(sorted_items)
    module_counts = _module_counts(sorted_items)
    grouped = _group_by_severity(sorted_items)
    sorted_incidents = sort_incidents(incidents)

    lines: list[str] = [
        "# Cloud Security Risk Report",
        "",
        f"Generated: {report_date.isoformat()}",
        "",
        "## Executive Summary",
        "",
        (
            f"This report consolidates {len(sorted_items)} "
            f"{'finding' if len(sorted_items) == 1 else 'findings'} "
            "from offline cloud security analyzers."
        ),
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]

    for severity in SEVERITY_ORDER:
        lines.append(f"| {_severity_label(severity)} | {severity_counts.get(severity, 0)} |")

    lines.extend(
        [
            "",
            "## Module Coverage",
            "",
            "| Module | Findings |",
            "| --- | ---: |",
        ]
    )

    for module, count in sorted(module_counts.items()):
        lines.append(f"| {module} | {count} |")

    lines.extend(
        [
            "",
            "## Source Files",
            "",
            "The source files below are generated analyzer outputs and are not committed to the repository.",
            "",
        ]
    )
    for path in source_files:
        lines.append(f"- `{path}`")

    if sorted_incidents:
        lines.extend(
            [
                "",
                "## Correlated Incidents",
                "",
                (
                    "These incidents group related CloudTrail signals by actor, source IP, "
                    "and a bounded time window. They support triage and do not prove malicious intent."
                ),
                "",
                "| Incident | Severity | Confidence | Actor | Window | Findings / Events |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for incident in sorted_incidents:
            lines.append(
                f"| `{incident.incident_id}` | {_severity_label(incident.severity)} | "
                f"{incident.confidence.capitalize()} | `{incident.actor}` | "
                f"{incident.first_seen} to {incident.last_seen} | "
                f"{incident.finding_count} / {incident.event_count} |"
            )

        for incident in sorted_incidents:
            event_label = "event" if incident.event_count == 1 else "events"
            finding_label = "finding" if incident.finding_count == 1 else "findings"
            lines.extend(
                [
                    "",
                    f"### {incident.incident_id}: {incident.title}",
                    "",
                    f"- Actor and source: `{incident.actor}` from `{incident.source_ip}`",
                    f"- Window: {incident.first_seen} to {incident.last_seen}",
                    f"- Severity and confidence: {incident.severity.capitalize()} / {incident.confidence.capitalize()}",
                    f"- Correlated rules: {', '.join(incident.rule_ids)}",
                    (
                        f"- Events and findings: {incident.event_count} {event_label}, "
                        f"{incident.finding_count} {finding_label}"
                    ),
                    f"- Resources: {', '.join(incident.resources)}",
                    f"- Summary: {incident.summary}",
                    f"- Recommended actions: {' '.join(incident.recommended_actions)}",
                    f"- References: {', '.join(incident.references)}",
                ]
            )

    lines.extend(["", "## Findings", ""])

    if not sorted_items:
        lines.append("No findings were detected.")
        lines.append("")
        return "\n".join(lines)

    for severity in SEVERITY_ORDER:
        severity_findings = grouped.get(severity, [])
        if not severity_findings:
            continue

        lines.extend([f"### {_severity_label(severity)}", ""])
        for finding in severity_findings:
            lines.extend(
                [
                    f"#### {finding.rule_id}: {finding.title}",
                    "",
                    f"- Module: `{finding.module}`",
                    f"- Category: `{finding.category}`",
                    f"- Resource: `{finding.resource_type}/{finding.resource_id}`",
                    f"- Evidence: {finding.evidence}",
                    f"- Impact: {finding.impact}",
                    f"- Remediation: {finding.remediation}",
                    f"- Metadata: {_format_metadata(finding)}",
                ]
            )
            if finding.references:
                lines.append(f"- References: {', '.join(finding.references)}")
            lines.append("")

    return "\n".join(lines)


def write_report(path: Path, report: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a Markdown cloud security risk report from finding JSON files."
    )
    parser.add_argument(
        "--findings",
        action="append",
        type=Path,
        required=True,
        help="Path to a findings JSON file. Repeat this option to merge multiple modules.",
    )
    parser.add_argument("--output", type=Path, required=True, help="Markdown report output path.")
    parser.add_argument(
        "--incidents",
        action="append",
        type=Path,
        default=[],
        help="Optional incidents JSON path. Repeat to merge incident files.",
    )
    parser.add_argument(
        "--report-date",
        type=_parse_report_date,
        help="Report date in YYYY-MM-DD format. Defaults to the current local date.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        findings = load_all_findings(args.findings)
        incidents = load_all_incidents(args.incidents)
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))

    report = render_report(
        findings,
        source_files=[*args.findings, *args.incidents],
        report_date=args.report_date,
        incidents=incidents,
    )
    write_report(args.output, report)
    print(f"Report saved to {args.output}")
    print(f"Findings included: {len(findings)}")
    print(f"Incidents included: {len(incidents)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
