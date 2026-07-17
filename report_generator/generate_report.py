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

from cloud_analysis import AnalysisSummary, load_analysis_summary_file
from cloud_findings import Finding, load_findings_file, sort_findings
from cloud_incidents import Incident, load_incidents_file, sort_incidents
from cloud_remediation import (
    RemediationPlan,
    build_remediation_plan,
    write_remediation_plan,
)
from cloud_rules import load_builtin_catalog, validate_rule_emission
from cloud_timeline import (
    AttackTimeline,
    activity_label,
    build_attack_timeline,
    build_incident_narrative,
    write_attack_timeline,
)

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


def load_all_analysis_summaries(paths: Iterable[Path]) -> list[AnalysisSummary]:
    """Load analysis summaries in deterministic module order."""

    summaries = [load_analysis_summary_file(path) for path in paths]
    return sorted(
        summaries,
        key=lambda item: (
            item.module,
            item.input_format,
            item.analyzer_version,
            item.input_file_count,
        ),
    )


def _severity_counts(findings: Iterable[Finding]) -> Counter[str]:
    return Counter(finding.severity.lower() for finding in findings)


def _module_counts(findings: Iterable[Finding]) -> Counter[str]:
    return Counter(finding.module for finding in findings)


def _validate_rule_context(findings: Iterable[Finding]) -> None:
    for finding in findings:
        validate_rule_emission(
            finding.rule_id,
            finding.module,
            finding.severity,
            require_known=False,
        )


def _triggered_rule_context(findings: Iterable[Finding]) -> list[str]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.rule_id].append(finding)

    if not grouped:
        return []

    catalog = load_builtin_catalog()
    frameworks = {framework.id: framework for framework in catalog.frameworks}
    lines = [
        "",
        "## Triggered Rule Context",
        "",
        (
            "Confidence describes how directly the available evidence supports the "
            "rule condition. It does not establish malicious intent."
        ),
        "",
        (
            "`direct` mappings substantially match the detector condition; `related` "
            "mappings provide useful context without claiming equivalent coverage."
        ),
        "",
        (
            "| Rule | Catalog Title | Confidence | Finding Severities | "
            "Findings | Control Mappings |"
        ),
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for rule_id, rule_findings in sorted(grouped.items()):
        rule = catalog.get(rule_id)
        severity_set = {finding.severity for finding in rule_findings}
        severities = ", ".join(
            severity for severity in SEVERITY_ORDER if severity in severity_set
        )
        if rule is None:
            title = rule_findings[0].title.replace("|", "\\|")
            confidence = "Not cataloged"
            mappings = "Not cataloged"
        else:
            title = rule.title.replace("|", "\\|")
            confidence = rule.confidence.capitalize()
            mappings = "<br>".join(
                (
                    f"{frameworks[mapping.framework].name} "
                    f"{mapping.control_id} ({mapping.relationship})"
                )
                for mapping in rule.mappings
            )
        lines.append(
            f"| `{rule_id}` | {title} | {confidence} | {severities} | "
            f"{len(rule_findings)} | {mappings} |"
        )
    return lines


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


def _validate_summary_counts(
    findings: Iterable[Finding],
    incidents: Iterable[Incident],
    summaries: Iterable[AnalysisSummary],
) -> None:
    summaries_by_module: dict[str, list[AnalysisSummary]] = defaultdict(list)
    for summary in summaries:
        summaries_by_module[summary.module].append(summary)
    finding_counts = _module_counts(findings)
    incident_counts = Counter(incident.module for incident in incidents)
    result_modules = set(finding_counts) | set(incident_counts)
    missing_modules = (
        sorted(result_modules.difference(summaries_by_module))
        if summaries_by_module
        else []
    )
    if missing_modules:
        raise ValueError(
            "Analysis summaries are missing for result module(s): "
            + ", ".join(missing_modules)
            + "."
        )
    for module, module_summaries in summaries_by_module.items():
        expected_findings = sum(summary.finding_count for summary in module_summaries)
        actual_findings = finding_counts.get(module, 0)
        if expected_findings != actual_findings:
            raise ValueError(
                f"Analysis summaries declare {expected_findings} {module} finding(s), "
                f"but the report received {actual_findings}."
            )
        expected_incidents = sum(summary.incident_count for summary in module_summaries)
        actual_incidents = incident_counts.get(module, 0)
        if expected_incidents != actual_incidents:
            raise ValueError(
                f"Analysis summaries declare {expected_incidents} {module} incident(s), "
                f"but the report received {actual_incidents}."
            )


def _resource_coverage_label(summary: AnalysisSummary) -> str:
    return "; ".join(
        f"{item.resource_type}: {item.evaluated_count}/{item.discovered_count}"
        for item in summary.resource_coverage
    )


def _escape_table_text(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _render_remediation_plan(plan: RemediationPlan) -> list[str]:
    lines = [
        "",
        "## Prioritized Remediation Plan",
        "",
        (
            "Priorities use the transparent rules below rather than an opaque "
            "numeric risk score. Incident response and configuration hardening "
            "remain separate work types."
        ),
        "",
        "| Priority | Meaning |",
        "| --- | --- |",
        (
            "| P0 | Immediate response for critical incidents, or high-severity "
            "incidents with high correlation confidence. |"
        ),
        (
            "| P1 | Urgent investigation or hardening for other incidents, "
            "critical findings, and configuration linked to a P0 incident. |"
        ),
        (
            "| P2 | Near-term hardening for high findings and configuration "
            "linked to another incident. |"
        ),
        "| P3 | Planned hardening for medium, low, and informational findings. |",
        "",
    ]
    if not plan.actions:
        lines.append("No remediation actions were generated.")
        return lines

    lines.extend(
        [
            (
                "| Priority | Work Item | Type | Severity / Confidence | "
                "Priority Basis | Required Action |"
            ),
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for action in plan.actions:
        work_type = action.work_type.replace("-", " ").capitalize()
        required_actions = "<br>".join(
            _escape_table_text(item) for item in action.actions
        )
        lines.append(
            f"| **{action.priority}** | `{action.action_id}` "
            f"{_escape_table_text(action.title)} | {work_type} | "
            f"{action.severity.capitalize()} / {action.confidence.capitalize()} | "
            f"{_escape_table_text(action.rationale)} | {required_actions} |"
        )
    return lines


def _timeline_time_label(first_seen: str, last_seen: str) -> str:
    if first_seen == last_seen:
        return first_seen
    return f"{first_seen} to {last_seen}"


def _render_attack_timeline(timeline: AttackTimeline) -> list[str]:
    if (
        timeline.source_cloudtrail_finding_count == 0
        and timeline.source_incident_count == 0
    ):
        return []

    lines = [
        "",
        "## Attack Timeline",
        "",
        (
            "This chronology orders observed CloudTrail finding evidence. Activity "
            "labels describe the recorded control-plane action; they do not establish "
            "malicious intent, attack phase, or causation."
        ),
        "",
        (
            f"Timeline coverage: {len(timeline.entries)} of "
            f"{timeline.source_cloudtrail_finding_count} CloudTrail findings included; "
            f"{len(timeline.omissions)} omitted because required chronological evidence "
            "was unavailable or invalid."
        ),
        "",
    ]
    if timeline.entries:
        lines.extend(
            [
                (
                    "| Time (UTC) | Activity | Observation | Signal Context | "
                    "Why It Matters |"
                ),
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for entry in timeline.entries:
            event_names = (
                ", ".join(entry.event_names)
                if entry.event_names
                else "Event name not recorded"
            )
            incident_context = (
                ", ".join(f"`{incident_id}`" for incident_id in entry.incident_ids)
                if entry.incident_ids
                else "No correlated incident"
            )
            observation = (
                f"{entry.observation} Actor `{entry.actor}` from `{entry.source_ip}`; "
                f"event(s): {event_names}; resource: `{entry.resource}`."
            )
            signal_context = (
                f"`{entry.rule_id}`; {entry.severity.capitalize()} severity; "
                f"{entry.confidence.capitalize()} confidence; {incident_context}"
            )
            lines.append(
                f"| {_escape_table_text(_timeline_time_label(entry.first_seen, entry.last_seen))} "
                f"| {_escape_table_text(activity_label(entry.activity_type))} "
                f"| {_escape_table_text(observation)} "
                f"| {_escape_table_text(signal_context)} "
                f"| {_escape_table_text(entry.significance)} |"
            )
    else:
        lines.append("No finding contained enough evidence for a timeline entry.")

    if timeline.omissions:
        lines.extend(
            [
                "",
                "### Timeline Omissions",
                "",
                (
                    "Omissions remain visible so missing or invalid timestamps and event "
                    "identifiers are not mistaken for complete chronological coverage."
                ),
                "",
                "| Rule | Resource | Reason |",
                "| --- | --- | --- |",
            ]
        )
        for omission in timeline.omissions:
            lines.append(
                f"| `{_escape_table_text(omission.rule_id)}` | "
                f"`{_escape_table_text(omission.resource)}` | "
                f"`{_escape_table_text(omission.reason)}` |"
            )
    return lines


def render_report(
    findings: list[Finding],
    *,
    source_files: Iterable[Path],
    report_date: date | None = None,
    incidents: Iterable[Incident] = (),
    analysis_summaries: Iterable[AnalysisSummary] = (),
) -> str:
    report_date = report_date or date.today()
    sorted_items = sort_findings(findings)
    severity_counts = _severity_counts(sorted_items)
    module_counts = _module_counts(sorted_items)
    grouped = _group_by_severity(sorted_items)
    sorted_incidents = sort_incidents(incidents)
    sorted_summaries = sorted(
        analysis_summaries,
        key=lambda item: (
            item.module,
            item.input_format,
            item.analyzer_version,
            item.input_file_count,
        ),
    )
    _validate_summary_counts(sorted_items, sorted_incidents, sorted_summaries)
    _validate_rule_context(sorted_items)
    timeline = build_attack_timeline(sorted_items, sorted_incidents)
    remediation_plan = build_remediation_plan(sorted_items, sorted_incidents)

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

    if sorted_summaries:
        lines.extend(
            [
                "",
                "## Analysis Coverage",
                "",
                (
                    "Resource counts use `evaluated/discovered`. A partial result means "
                    "one or more evidence gaps affected analysis coverage."
                ),
                "",
                (
                    "| Module | Input | Coverage | Evaluated Resources | "
                    "Skipped Evidence | Warnings | Findings |"
                ),
                "| --- | --- | --- | --- | ---: | ---: | ---: |",
            ]
        )
        for summary in sorted_summaries:
            skipped_count = sum(item.count for item in summary.skipped_evidence)
            lines.append(
                f"| {summary.module} | {summary.input_format} "
                f"({summary.input_file_count} file(s)) | {summary.coverage_status} | "
                f"{_resource_coverage_label(summary)} | {skipped_count} | "
                f"{len(summary.warnings)} | {summary.finding_count} |"
            )

        evidence_gaps = [
            (summary.module, item)
            for summary in sorted_summaries
            for item in summary.skipped_evidence
        ]
        if evidence_gaps:
            lines.extend(
                [
                    "",
                    "### Skipped Evidence",
                    "",
                    "| Module | Code | Count | Coverage Impact | Reason |",
                    "| --- | --- | ---: | --- | --- |",
                ]
            )
            for module, item in evidence_gaps:
                impact = "yes" if item.affects_coverage else "no"
                lines.append(
                    f"| {module} | `{item.code}` | {item.count} | {impact} | "
                    f"{item.reason} |"
                )

        analysis_warnings = [
            (summary.module, warning)
            for summary in sorted_summaries
            for warning in summary.warnings
        ]
        if analysis_warnings:
            lines.extend(["", "### Analysis Warnings", ""])
            for module, warning in analysis_warnings:
                lines.append(f"- `{module}`: {warning}")
    else:
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

    lines.extend(_render_attack_timeline(timeline))
    lines.extend(_render_remediation_plan(remediation_plan))
    lines.extend(_triggered_rule_context(sorted_items))

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
            narrative = build_incident_narrative(incident, timeline)
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
                    f"- Observed sequence: {narrative.observed_sequence}",
                    f"- Analyst context: {narrative.analyst_context}",
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
        "--analysis-summary",
        action="append",
        type=Path,
        default=[],
        help="Optional analysis summary JSON path. Repeat to merge module coverage.",
    )
    parser.add_argument(
        "--report-date",
        type=_parse_report_date,
        help="Report date in YYYY-MM-DD format. Defaults to the current local date.",
    )
    parser.add_argument(
        "--remediation-output",
        type=Path,
        help="Optional versioned remediation plan JSON output path.",
    )
    parser.add_argument(
        "--timeline-output",
        type=Path,
        help="Optional versioned attack timeline JSON output path.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        findings = load_all_findings(args.findings)
        incidents = load_all_incidents(args.incidents)
        analysis_summaries = load_all_analysis_summaries(args.analysis_summary)
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))

    report = render_report(
        findings,
        source_files=[*args.findings, *args.incidents, *args.analysis_summary],
        report_date=args.report_date,
        incidents=incidents,
        analysis_summaries=analysis_summaries,
    )
    write_report(args.output, report)
    if args.remediation_output is not None:
        plan = build_remediation_plan(findings, incidents)
        write_remediation_plan(args.remediation_output, plan)
        print(f"Remediation plan saved to {args.remediation_output}")
    if args.timeline_output is not None:
        timeline = build_attack_timeline(findings, incidents)
        write_attack_timeline(args.timeline_output, timeline)
        print(f"Attack timeline saved to {args.timeline_output}")
    print(f"Report saved to {args.output}")
    print(f"Findings included: {len(findings)}")
    print(f"Incidents included: {len(incidents)}")
    print(f"Analysis summaries included: {len(analysis_summaries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
