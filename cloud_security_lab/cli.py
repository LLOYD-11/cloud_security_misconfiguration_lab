"""Unified command-line interface for all lab analyzers and reports."""

from __future__ import annotations

import argparse
import sys
import sysconfig
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Callable, Sequence

from cloud_analysis import AnalysisSummary, SkippedEvidence, write_analysis_summary
from cloud_findings import Finding, write_findings
from cloud_incidents import Incident, write_incidents
from cloud_security_lab import __version__
from cloud_security_lab.analysis import build_analysis_summary
from cloud_security_lab.normalizers import (
    apply_network_reachability_context,
    load_aws_cloudtrail_environment,
    load_aws_ec2_environment,
    load_aws_iam_environment,
    load_aws_s3_environment,
    load_network_reachability_context,
    write_normalized_environment,
)
from cloudtrail_detector.correlation import DEFAULT_CORRELATION_WINDOW_MINUTES
from cloudtrail_detector.detector import (
    analyze_activity as analyze_cloudtrail_activity,
    analyze_environment as analyze_cloudtrail,
    load_environment as load_cloudtrail,
    print_findings as print_cloudtrail,
    print_incidents as print_cloudtrail_incidents,
)
from iam_analyzer.analyzer import (
    analyze_environment as analyze_iam,
    load_environment as load_iam,
    print_findings as print_iam,
)
from network_analyzer.analyzer import (
    analyze_environment as analyze_network,
    load_environment as load_network,
    print_findings as print_network,
)
from report_generator.generate_report import (
    load_all_analysis_summaries,
    load_all_findings,
    load_all_incidents,
    render_report,
    write_report,
)
from storage_analyzer.analyzer import (
    analyze_environment as analyze_storage,
    load_environment as load_storage,
    print_findings as print_storage,
)

Loader = Callable[[Path], dict[str, Any]]
Analyzer = Callable[[dict[str, Any]], list[Finding]]
FindingPrinter = Callable[[list[Finding]], None]


@dataclass(frozen=True)
class AnalyzerSpec:
    label: str
    loader: Loader
    analyzer: Analyzer
    printer: FindingPrinter
    sample_path: Path


ANALYZERS = {
    "iam": AnalyzerSpec(
        label="IAM",
        loader=load_iam,
        analyzer=analyze_iam,
        printer=print_iam,
        sample_path=Path("iam/sample_iam_environment.json"),
    ),
    "storage": AnalyzerSpec(
        label="Storage",
        loader=load_storage,
        analyzer=analyze_storage,
        printer=print_storage,
        sample_path=Path("storage/sample_storage_environment.json"),
    ),
    "network": AnalyzerSpec(
        label="Network",
        loader=load_network,
        analyzer=analyze_network,
        printer=print_network,
        sample_path=Path("network/sample_network_environment.json"),
    ),
    "cloudtrail": AnalyzerSpec(
        label="CloudTrail",
        loader=load_cloudtrail,
        analyzer=analyze_cloudtrail,
        printer=print_cloudtrail,
        sample_path=Path("cloudtrail/sample_cloudtrail_events.json"),
    ),
}


def _default_sample_root() -> Path:
    repository_samples = Path(__file__).resolve().parents[1] / "sample_data"
    if repository_samples.is_dir():
        return repository_samples
    return (
        Path(sysconfig.get_path("data"))
        / "share"
        / "cloud-security-misconfiguration-lab"
        / "sample_data"
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _report_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("date must use YYYY-MM-DD format") from exc


def _analyze(
    module: str,
    input_path: Path,
    *,
    failure_threshold: int = 5,
    failure_window_minutes: int = 10,
) -> list[Finding]:
    spec = ANALYZERS[module]
    environment = spec.loader(input_path)
    if module == "cloudtrail":
        return analyze_cloudtrail(
            environment,
            failure_threshold=failure_threshold,
            failure_window_minutes=failure_window_minutes,
        )
    return spec.analyzer(environment)


def _run_analyze(args: argparse.Namespace) -> int:
    input_paths: list[Path] = args.input
    if args.module != "cloudtrail" and (
        args.failure_threshold != 5
        or args.failure_window_minutes != 10
        or args.correlation_window_minutes != DEFAULT_CORRELATION_WINDOW_MINUTES
        or args.incidents_output is not None
    ):
        raise ValueError(
            "CloudTrail thresholds, correlation settings, and incident output are only "
            "valid for cloudtrail"
        )
    if args.reachability_context is not None and args.module != "network":
        raise ValueError("--reachability-context is only valid for network analysis")

    iam_auxiliary_options = args.credential_report is not None or args.as_of is not None
    normalization_warnings: tuple[str, ...] = ()
    skipped_evidence: tuple[SkippedEvidence, ...] = ()
    incidents: list[Incident] = []
    analysis_parameters: dict[str, str] = {}
    if args.module == "cloudtrail":
        analysis_parameters = {
            "correlation_window_minutes": str(args.correlation_window_minutes),
            "failure_threshold": str(args.failure_threshold),
            "failure_window_minutes": str(args.failure_window_minutes),
        }
    if args.input_format == "simplified":
        if len(input_paths) != 1:
            raise ValueError("Simplified analyzer input accepts exactly one JSON file")
        if iam_auxiliary_options or args.normalized_output is not None:
            raise ValueError(
                "--credential-report, --as-of, and --normalized-output require "
                "--input-format aws"
            )
        normalized_environment = ANALYZERS[args.module].loader(input_paths[0])
        if args.reachability_context is not None:
            assessments = load_network_reachability_context(args.reachability_context)
            reachability_result = apply_network_reachability_context(
                normalized_environment,
                assessments,
            )
            normalized_environment = reachability_result.environment
            normalization_warnings = reachability_result.warnings
        if args.module == "cloudtrail":
            cloudtrail_result = analyze_cloudtrail_activity(
                normalized_environment,
                failure_threshold=args.failure_threshold,
                failure_window_minutes=args.failure_window_minutes,
                correlation_window_minutes=args.correlation_window_minutes,
            )
            findings = list(cloudtrail_result.findings)
            incidents = list(cloudtrail_result.incidents)
        else:
            findings = ANALYZERS[args.module].analyzer(normalized_environment)
    else:
        if args.module != "cloudtrail" and len(input_paths) != 1:
            raise ValueError(
                "Multiple AWS input files are supported only for the cloudtrail module"
            )
        if args.module == "iam":
            if args.credential_report is None:
                raise ValueError("--credential-report is required for AWS IAM input")
            analysis_date = args.as_of or date.today()
            iam_result = load_aws_iam_environment(
                input_paths[0],
                args.credential_report,
                as_of=analysis_date,
            )
            analysis_parameters = {"as_of": analysis_date.isoformat()}
            normalized_environment = iam_result.environment
            normalization_warnings = iam_result.warnings
            skipped_evidence = iam_result.skipped_evidence
            findings = analyze_iam(normalized_environment)
        elif args.module == "storage":
            if iam_auxiliary_options:
                raise ValueError("--credential-report and --as-of are only valid for AWS IAM input")
            s3_result = load_aws_s3_environment(input_paths[0])
            normalized_environment = s3_result.environment
            normalization_warnings = s3_result.warnings
            skipped_evidence = s3_result.skipped_evidence
            findings = analyze_storage(normalized_environment)
        elif args.module == "network":
            if iam_auxiliary_options:
                raise ValueError("--credential-report and --as-of are only valid for AWS IAM input")
            ec2_result = load_aws_ec2_environment(input_paths[0])
            normalized_environment = ec2_result.environment
            normalization_warnings = ec2_result.warnings
            skipped_evidence = ec2_result.skipped_evidence
            if args.reachability_context is not None:
                assessments = load_network_reachability_context(args.reachability_context)
                reachability_result = apply_network_reachability_context(
                    normalized_environment,
                    assessments,
                )
                normalized_environment = reachability_result.environment
                normalization_warnings += reachability_result.warnings
            findings = analyze_network(normalized_environment)
        elif args.module == "cloudtrail":
            if iam_auxiliary_options:
                raise ValueError(
                    "--credential-report and --as-of are only valid for AWS IAM input"
                )
            cloudtrail_normalization = load_aws_cloudtrail_environment(input_paths)
            normalized_environment = cloudtrail_normalization.environment
            normalization_warnings = cloudtrail_normalization.warnings
            skipped_evidence = cloudtrail_normalization.skipped_evidence
            cloudtrail_analysis = analyze_cloudtrail_activity(
                normalized_environment,
                failure_threshold=args.failure_threshold,
                failure_window_minutes=args.failure_window_minutes,
                correlation_window_minutes=args.correlation_window_minutes,
            )
            findings = list(cloudtrail_analysis.findings)
            incidents = list(cloudtrail_analysis.incidents)
        else:
            raise ValueError(f"Unsupported analyzer module: {args.module}")

        if args.normalized_output:
            write_normalized_environment(args.normalized_output, normalized_environment)
            print(f"Normalized environment saved to {args.normalized_output}")
    summary: AnalysisSummary | None = None
    if args.summary_output:
        input_file_count = len(input_paths)
        if args.credential_report is not None:
            input_file_count += 1
        if args.reachability_context is not None:
            input_file_count += 1
        summary = build_analysis_summary(
            module=args.module,
            environment=normalized_environment,
            input_format=args.input_format,
            input_file_count=input_file_count,
            finding_count=len(findings),
            incident_count=len(incidents),
            parameters=analysis_parameters,
            warnings=normalization_warnings,
            skipped_evidence=skipped_evidence,
        )
    for warning in normalization_warnings:
        print(f"Warning: {warning}", file=sys.stderr)
    ANALYZERS[args.module].printer(findings)
    if args.module == "cloudtrail":
        print_cloudtrail_incidents(incidents)
    if args.output:
        write_findings(args.output, findings)
        print(f"Findings saved to {args.output}")
    if args.incidents_output:
        write_incidents(args.incidents_output, incidents)
        print(f"Incidents saved to {args.incidents_output}")
    if args.summary_output and summary is not None:
        write_analysis_summary(args.summary_output, summary)
        print(
            f"Analysis summary saved to {args.summary_output} "
            f"({summary.coverage_status} coverage)"
        )
    return 0


def _run_report(args: argparse.Namespace) -> int:
    findings = load_all_findings(args.findings)
    incidents = load_all_incidents(args.incidents)
    analysis_summaries = load_all_analysis_summaries(args.analysis_summary)
    report = render_report(
        findings,
        source_files=[*args.findings, *args.incidents, *args.analysis_summary],
        report_date=args.report_date,
        incidents=incidents,
        analysis_summaries=analysis_summaries,
    )
    write_report(args.output, report)
    print(f"Report saved to {args.output}")
    print(f"Findings included: {len(findings)}")
    print(f"Incidents included: {len(incidents)}")
    print(f"Analysis summaries included: {len(analysis_summaries)}")
    return 0


def _run_demo(args: argparse.Namespace) -> int:
    finding_paths: list[Path] = []
    incident_paths: list[Path] = []
    summary_paths: list[Path] = []
    all_findings: list[Finding] = []
    all_incidents: list[Incident] = []
    all_summaries: list[AnalysisSummary] = []

    for module, spec in ANALYZERS.items():
        input_path = args.sample_root / spec.sample_path
        environment = spec.loader(input_path)
        if module == "cloudtrail":
            cloudtrail_result = analyze_cloudtrail_activity(environment)
            findings = list(cloudtrail_result.findings)
            incidents = list(cloudtrail_result.incidents)
            incident_path = args.output_dir / "cloudtrail_incidents.json"
            write_incidents(incident_path, incidents)
            incident_paths.append(incident_path)
            all_incidents.extend(incidents)
            print(f"CloudTrail incidents: {len(incidents)} -> {incident_path}")
        else:
            findings = spec.analyzer(environment)
        output_path = args.output_dir / f"{module}_findings.json"
        write_findings(output_path, findings)
        finding_paths.append(output_path)
        all_findings.extend(findings)
        print(f"{spec.label}: {len(findings)} finding(s) -> {output_path}")
        summary = build_analysis_summary(
            module=module,
            environment=environment,
            input_format="simplified",
            input_file_count=1,
            finding_count=len(findings),
            incident_count=len(incidents) if module == "cloudtrail" else 0,
            parameters=(
                {
                    "correlation_window_minutes": str(
                        DEFAULT_CORRELATION_WINDOW_MINUTES
                    ),
                    "failure_threshold": "5",
                    "failure_window_minutes": "10",
                }
                if module == "cloudtrail"
                else {}
            ),
        )
        summary_path = args.output_dir / f"{module}_analysis_summary.json"
        write_analysis_summary(summary_path, summary)
        summary_paths.append(summary_path)
        all_summaries.append(summary)
        print(
            f"{spec.label} coverage: {summary.coverage_status} -> {summary_path}"
        )

    report_path = args.report_output or args.output_dir / "cloud_security_report.md"
    report = render_report(
        all_findings,
        source_files=[*finding_paths, *incident_paths, *summary_paths],
        report_date=args.report_date,
        incidents=all_incidents,
        analysis_summaries=all_summaries,
    )
    write_report(report_path, report)
    print(f"Combined report: {len(all_findings)} finding(s) -> {report_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-security-lab",
        description="Run offline AWS security analyzers and consolidate their findings.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Run one analyzer.")
    analyze_parser.add_argument("module", choices=tuple(ANALYZERS))
    analyze_parser.add_argument(
        "input",
        type=Path,
        nargs="+",
        help="Module input path. Native CloudTrail accepts multiple JSON or JSON.GZ files.",
    )
    analyze_parser.add_argument("--output", type=Path, help="Optional findings JSON output path.")
    analyze_parser.add_argument(
        "--summary-output",
        type=Path,
        help="Optional versioned analysis coverage and evidence-quality JSON output.",
    )
    analyze_parser.add_argument(
        "--incidents-output",
        type=Path,
        help="Optional correlated incident JSON output. Only valid for cloudtrail.",
    )
    analyze_parser.add_argument(
        "--input-format",
        choices=("simplified", "aws"),
        default="simplified",
        help="Input contract. AWS is supported by all four modules.",
    )
    analyze_parser.add_argument(
        "--credential-report",
        type=Path,
        help="AWS IAM credential report JSON or decoded CSV. Requires --input-format aws.",
    )
    analyze_parser.add_argument(
        "--as-of",
        type=_report_date,
        help="Date used for credential age calculations (YYYY-MM-DD; defaults to today).",
    )
    analyze_parser.add_argument(
        "--normalized-output",
        type=Path,
        help="Optional normalized analyzer environment output. Requires --input-format aws.",
    )
    analyze_parser.add_argument(
        "--reachability-context",
        type=Path,
        help=(
            "Optional versioned network path assessment. Valid only for network analysis and "
            "does not replace security-group evidence."
        ),
    )
    analyze_parser.add_argument(
        "--failure-threshold",
        type=_positive_int,
        default=5,
        help="CloudTrail API failure threshold. Only valid for the cloudtrail module.",
    )
    analyze_parser.add_argument(
        "--failure-window-minutes",
        type=_positive_int,
        default=10,
        help="CloudTrail API failure window. Only valid for the cloudtrail module.",
    )
    analyze_parser.add_argument(
        "--correlation-window-minutes",
        type=_positive_int,
        default=DEFAULT_CORRELATION_WINDOW_MINUTES,
        help="CloudTrail incident correlation window. Only valid for the cloudtrail module.",
    )
    analyze_parser.set_defaults(handler=_run_analyze)

    report_parser = subparsers.add_parser("report", help="Merge findings into a report.")
    report_parser.add_argument(
        "--findings",
        action="append",
        type=Path,
        required=True,
        help="Findings JSON path. Repeat to merge modules.",
    )
    report_parser.add_argument(
        "--incidents",
        action="append",
        type=Path,
        default=[],
        help="Optional incidents JSON path. Repeat to merge incident files.",
    )
    report_parser.add_argument(
        "--analysis-summary",
        action="append",
        type=Path,
        default=[],
        help="Optional analysis summary JSON path. Repeat to merge module coverage.",
    )
    report_parser.add_argument("--output", type=Path, required=True)
    report_parser.add_argument("--report-date", type=_report_date)
    report_parser.set_defaults(handler=_run_report)

    demo_parser = subparsers.add_parser("demo", help="Run all bundled repository samples.")
    demo_parser.add_argument(
        "--sample-root",
        type=Path,
        default=_default_sample_root(),
        help="Root directory containing iam, storage, network, and cloudtrail samples.",
    )
    demo_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/generated"),
        help="Directory for findings and the combined report.",
    )
    demo_parser.add_argument("--report-output", type=Path)
    demo_parser.add_argument("--report-date", type=_report_date)
    demo_parser.set_defaults(handler=_run_demo)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
