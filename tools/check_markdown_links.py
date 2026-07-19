"""Validate links in tracked Markdown without following unsafe network targets."""

from __future__ import annotations

import argparse
import html
import ipaddress
import re
import socket
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http.client import HTTPMessage
from pathlib import Path
from threading import BoundedSemaphore
from typing import IO, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from markdown_it import MarkdownIt
from markdown_it.token import Token

PROJECT_ROOT = Path(__file__).resolve().parents[1]
HTTP_SCHEMES = frozenset({"http", "https"})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
TRANSIENT_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
MAX_REDIRECTS = 8
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_RETRIES = 2
DEFAULT_WORKERS = 8
DEFAULT_PER_HOST = 2
USER_AGENT = (
    "cloud-security-misconfiguration-lab-link-check/2.2 "
    "(+https://github.com/LLOYD-11/cloud_security_misconfiguration_lab)"
)
_GITHUB_SLUG_PUNCTUATION = re.compile(r"[^\w\- ]", re.UNICODE)


@dataclass(frozen=True)
class LinkReference:
    source: Path
    line: int
    target: str
    kind: Literal["link", "image"]


@dataclass(frozen=True)
class LinkIssue:
    source: Path
    line: int
    target: str
    message: str


@dataclass(frozen=True)
class ExternalProbe:
    url: str
    status: int | None
    final_url: str
    error: str | None

    @property
    def passed(self) -> bool:
        return self.error is None and self.status is not None and 200 <= self.status < 400


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        return None


def repository_markdown_files(root: Path) -> tuple[Path, ...]:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "*.md",
        ],
        check=True,
        capture_output=True,
    )
    files: list[Path] = []
    for encoded in completed.stdout.split(b"\0"):
        if not encoded:
            continue
        relative = Path(encoded.decode("utf-8"))
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise RuntimeError(
                f"Repository Markdown path escapes root: {relative}"
            ) from error
        if not path.is_file():
            raise RuntimeError(f"Repository Markdown file is missing: {relative}")
        files.append(path)
    return tuple(sorted(files))


def extract_markdown_links(root: Path, files: Iterable[Path]) -> tuple[LinkReference, ...]:
    parser = MarkdownIt("commonmark").enable("table")
    references: list[LinkReference] = []
    for path in sorted(files):
        path = path.resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise ValueError(f"Markdown path escapes repository: {path}") from error
        tokens = parser.parse(path.read_text(encoding="utf-8"))
        for token in tokens:
            line = token.map[0] + 1 if token.map is not None else 1
            for child in token.children or ():
                if child.type == "link_open":
                    target = child.attrGet("href")
                    kind: Literal["link", "image"] = "link"
                elif child.type == "image":
                    target = child.attrGet("src")
                    kind = "image"
                else:
                    continue
                if target is not None:
                    target_text = str(target)
                    references.append(
                        LinkReference(
                            source=path,
                            line=line,
                            target=target_text,
                            kind=kind,
                        )
                    )
    return tuple(references)


def _github_slug(value: str) -> str:
    normalized = html.unescape(value).strip().lower()
    without_punctuation = _GITHUB_SLUG_PUNCTUATION.sub("", normalized)
    return without_punctuation.replace(" ", "-")


def _heading_text(token: Token) -> str:
    children = token.children or ()
    return "".join(
        child.content
        for child in children
        if child.type in {"text", "code_inline", "image"}
    )


def markdown_anchors(path: Path) -> frozenset[str]:
    parser = MarkdownIt("commonmark").enable("table")
    tokens = parser.parse(path.read_text(encoding="utf-8"))
    anchors: set[str] = set()
    for index, token in enumerate(tokens[:-1]):
        if token.type != "heading_open":
            continue
        base = _github_slug(_heading_text(tokens[index + 1]))
        candidate = base
        suffix = 0
        while candidate in anchors:
            suffix += 1
            candidate = f"{base}-{suffix}"
        anchors.add(candidate)
    return frozenset(anchors)


PathCaseStatus = Literal["exact", "mismatch", "missing", "unreadable"]


def _path_case_status(root: Path, target: Path) -> PathCaseStatus:
    relative = target.relative_to(root)
    current = root
    for part in relative.parts:
        try:
            names = {entry.name for entry in current.iterdir()}
        except OSError:
            return "unreadable"
        if part in names:
            current /= part
            continue
        if part.casefold() in {name.casefold() for name in names}:
            return "mismatch"
        return "missing"
    return "exact"


def validate_internal_links(
    root: Path,
    references: Iterable[LinkReference],
) -> tuple[LinkIssue, ...]:
    issues: list[LinkIssue] = []
    anchor_cache: dict[Path, frozenset[str]] = {}
    for reference in references:
        target = reference.target
        if target.startswith("//"):
            continue
        try:
            parsed = urlsplit(target)
        except ValueError as error:
            issues.append(
                LinkIssue(reference.source, reference.line, target, f"invalid URI: {error}")
            )
            continue
        scheme = parsed.scheme.lower()
        if scheme in HTTP_SCHEMES:
            continue
        if scheme == "mailto":
            if "@" not in parsed.path:
                issues.append(
                    LinkIssue(
                        reference.source,
                        reference.line,
                        target,
                        "invalid mailto address",
                    )
                )
            continue
        if scheme:
            issues.append(
                LinkIssue(
                    reference.source,
                    reference.line,
                    target,
                    f"unsupported URI scheme: {scheme}",
                )
            )
            continue
        decoded_path = unquote(parsed.path)
        if decoded_path.startswith("/"):
            issues.append(
                LinkIssue(
                    reference.source,
                    reference.line,
                    target,
                    "repository-local path must be relative",
                )
            )
            continue
        candidate = (
            (reference.source.parent / decoded_path).resolve()
            if decoded_path
            else reference.source
        )
        try:
            candidate.relative_to(root)
        except ValueError:
            issues.append(
                LinkIssue(
                    reference.source,
                    reference.line,
                    target,
                    "path escapes repository root",
                )
            )
            continue
        case_status = _path_case_status(root, candidate)
        if case_status == "mismatch":
            issues.append(
                LinkIssue(
                    reference.source,
                    reference.line,
                    target,
                    "target path has incorrect letter case",
                )
            )
            continue
        if case_status == "unreadable":
            issues.append(
                LinkIssue(
                    reference.source,
                    reference.line,
                    target,
                    "target path could not be inspected",
                )
            )
            continue
        if case_status == "missing" or not candidate.is_file():
            issues.append(
                LinkIssue(reference.source, reference.line, target, "target file does not exist")
            )
            continue

        fragment = unquote(parsed.fragment)
        if fragment and candidate.suffix.lower() == ".md":
            anchors = anchor_cache.setdefault(candidate, markdown_anchors(candidate))
            if fragment not in anchors:
                issues.append(
                    LinkIssue(
                        reference.source,
                        reference.line,
                        target,
                        f"Markdown anchor does not exist: #{fragment}",
                    )
                )
    return tuple(issues)


def external_targets(
    references: Iterable[LinkReference],
) -> dict[str, tuple[LinkReference, ...]]:
    grouped: dict[str, list[LinkReference]] = defaultdict(list)
    for reference in references:
        raw_target = (
            f"https:{reference.target}" if reference.target.startswith("//") else reference.target
        )
        try:
            parsed = urlsplit(raw_target)
        except ValueError:
            continue
        if parsed.scheme.lower() not in HTTP_SCHEMES:
            continue
        normalized = urlunsplit(
            (
                parsed.scheme.lower(),
                parsed.netloc,
                parsed.path,
                parsed.query,
                "",
            )
        )
        grouped[normalized].append(reference)
    return {url: tuple(items) for url, items in sorted(grouped.items())}


def _validate_public_url(url: str) -> None:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in HTTP_SCHEMES:
        raise ValueError("only HTTP and HTTPS links can be probed")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials are not allowed in public links")
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("public link has no hostname")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"invalid port: {error}") from error
    expected_port = 443 if scheme == "https" else 80
    if port is not None and port != expected_port:
        raise ValueError(f"non-default network port is not allowed: {port}")

    try:
        addresses = socket.getaddrinfo(
            hostname,
            port or expected_port,
            type=socket.SOCK_STREAM,
        )
    except OSError as error:
        raise URLError(f"hostname resolution failed: {error}") from error
    if not addresses:
        raise URLError("hostname did not resolve")
    for address_info in addresses:
        address_text = str(address_info[4][0]).split("%", 1)[0]
        address = ipaddress.ip_address(address_text)
        if not address.is_global:
            raise ValueError(f"hostname resolves to non-public address: {address}")


def _request_external_url(url: str, timeout: float) -> tuple[int, str]:
    opener = build_opener(_NoRedirectHandler())
    current_url = url
    for _ in range(MAX_REDIRECTS + 1):
        _validate_public_url(current_url)
        request = Request(
            current_url,
            headers={
                "Accept": "*/*",
                "Range": "bytes=0-0",
                "User-Agent": USER_AGENT,
            },
            method="GET",
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                response.read(1)
                return response.status, response.geturl()
        except HTTPError as error:
            try:
                if error.code not in REDIRECT_STATUSES:
                    return error.code, error.geturl()
                location = error.headers.get("Location")
                if not location:
                    return error.code, error.geturl()
                current_url = urljoin(current_url, location)
            finally:
                error.close()
    raise ValueError(f"redirect limit exceeded ({MAX_REDIRECTS})")


def probe_external_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
) -> ExternalProbe:
    if retries < 0:
        raise ValueError("retries must be zero or greater")
    last_error: str | None = None
    final_url = url
    status: int | None = None
    for attempt in range(retries + 1):
        try:
            status, final_url = _request_external_url(url, timeout)
            if 200 <= status < 400:
                return ExternalProbe(url, status, final_url, None)
            last_error = f"HTTP {status}"
            if status not in TRANSIENT_STATUSES:
                break
        except ValueError as error:
            return ExternalProbe(url, None, final_url, str(error))
        except (TimeoutError, URLError, OSError) as error:
            last_error = f"{type(error).__name__}: {error}"
        if attempt < retries:
            time.sleep(0.5 * (2**attempt))
    return ExternalProbe(url, status, final_url, last_error or "request failed")


ExternalProbeFunction = Callable[[str, float, int], ExternalProbe]


def validate_external_links(
    references: Iterable[LinkReference],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
    workers: int = DEFAULT_WORKERS,
    per_host: int = DEFAULT_PER_HOST,
    probe: ExternalProbeFunction = probe_external_url,
) -> tuple[tuple[LinkIssue, ...], int]:
    if workers < 1 or per_host < 1:
        raise ValueError("workers and per-host concurrency must be positive")
    targets = external_targets(references)
    semaphores = {
        urlsplit(url).hostname or "": BoundedSemaphore(per_host) for url in targets
    }

    def run_probe(url: str) -> ExternalProbe:
        hostname = urlsplit(url).hostname or ""
        with semaphores[hostname]:
            return probe(url, timeout, retries)

    results: dict[str, ExternalProbe] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(run_probe, url): url for url in targets}
        for future in as_completed(futures):
            url = futures[future]
            try:
                results[url] = future.result()
            except Exception as error:
                results[url] = ExternalProbe(
                    url,
                    None,
                    url,
                    f"{type(error).__name__}: {error}",
                )

    issues: list[LinkIssue] = []
    for url, references_for_url in targets.items():
        result = results[url]
        if result.passed:
            continue
        first = references_for_url[0]
        suffix = (
            f"; {len(references_for_url)} references use this URL"
            if len(references_for_url) > 1
            else ""
        )
        issues.append(
            LinkIssue(
                first.source,
                first.line,
                url,
                f"{result.error or 'request failed'}{suffix}",
            )
        )
    return tuple(issues), len(targets)


def _print_issues(root: Path, issues: Iterable[LinkIssue]) -> None:
    for issue in sorted(
        issues,
        key=lambda item: (str(item.source), item.line, item.target),
    ):
        source = issue.source.relative_to(root)
        print(
            f"{source}:{issue.line}: {issue.message}: {issue.target}",
            file=sys.stderr,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("internal", "external"))
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--per-host", type=int, default=DEFAULT_PER_HOST)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    files = repository_markdown_files(root)
    references = extract_markdown_links(root, files)
    if args.mode == "internal":
        issues = validate_internal_links(root, references)
        external_reference_count = sum(
            len(items) for items in external_targets(references).values()
        )
        checked_count = len(references) - external_reference_count
        if issues:
            _print_issues(root, issues)
            return 1
        print(
            f"Internal links: {checked_count} references passed "
            f"across {len(files)} Markdown files."
        )
        return 0

    issues, checked_count = validate_external_links(
        references,
        timeout=args.timeout,
        retries=args.retries,
        workers=args.workers,
        per_host=args.per_host,
    )
    if issues:
        _print_issues(root, issues)
        return 1
    reference_count = sum(len(items) for items in external_targets(references).values())
    print(
        f"External links: {checked_count} unique URLs passed "
        f"for {reference_count} references across {len(files)} Markdown files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
