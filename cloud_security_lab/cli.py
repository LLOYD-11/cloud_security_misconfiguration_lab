"""Unified command-line interface for all lab analyzers and reports."""

from __future__ import annotations

import argparse
import sysconfig
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Callable, Sequence

from cloud_findings import Finding, write_findings
from cloud_security_lab import __version__
from cloudtrail_detector.detector import (
    analyze_environment as analyze_cloudtrail,
    load_environment as load_cloudtrail,
    print_findings as print_cloudtrail,
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
from report_generator.generate_report import load_all_findings, render_report, write_report
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
        raise argparse.ArgumentTypeError("report date must use YYYY-MM-DD format") from exc


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
    if args.module != "cloudtrail" and (
        args.failure_threshold != 5 or args.failure_window_minutes != 10
    ):
        raise ValueError(
            "--failure-threshold and --failure-window-minutes are only valid for cloudtrail"
        )
    findings = _analyze(
        args.module,
        args.input,
        failure_threshold=args.failure_threshold,
        failure_window_minutes=args.failure_window_minutes,
    )
    ANALYZERS[args.module].printer(findings)
    if args.output:
        write_findings(args.output, findings)
        print(f"Findings saved to {args.output}")
    return 0


def _run_report(args: argparse.Namespace) -> int:
    findings = load_all_findings(args.findings)
    report = render_report(
        findings,
        source_files=args.findings,
        report_date=args.report_date,
    )
    write_report(args.output, report)
    print(f"Report saved to {args.output}")
    print(f"Findings included: {len(findings)}")
    return 0


def _run_demo(args: argparse.Namespace) -> int:
    finding_paths: list[Path] = []
    all_findings: list[Finding] = []

    for module, spec in ANALYZERS.items():
        input_path = args.sample_root / spec.sample_path
        findings = _analyze(module, input_path)
        output_path = args.output_dir / f"{module}_findings.json"
        write_findings(output_path, findings)
        finding_paths.append(output_path)
        all_findings.extend(findings)
        print(f"{spec.label}: {len(findings)} finding(s) -> {output_path}")

    report_path = args.report_output or args.output_dir / "cloud_security_report.md"
    report = render_report(
        all_findings,
        source_files=finding_paths,
        report_date=args.report_date,
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
    analyze_parser.add_argument("input", type=Path, help="Path to the module input JSON file.")
    analyze_parser.add_argument("--output", type=Path, help="Optional findings JSON output path.")
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
    analyze_parser.set_defaults(handler=_run_analyze)

    report_parser = subparsers.add_parser("report", help="Merge findings into a report.")
    report_parser.add_argument(
        "--findings",
        action="append",
        type=Path,
        required=True,
        help="Findings JSON path. Repeat to merge modules.",
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
