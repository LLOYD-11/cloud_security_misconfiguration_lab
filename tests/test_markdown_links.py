import io
import socket
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, call, patch
from urllib.error import HTTPError, URLError

from tools.check_markdown_links import (
    ExternalProbe,
    LinkIssue,
    LinkReference,
    _github_slug,
    _NoRedirectHandler,
    _request_external_url,
    _validate_public_url,
    external_targets,
    extract_markdown_links,
    main,
    markdown_anchors,
    probe_external_url,
    repository_markdown_files,
    validate_external_links,
    validate_internal_links,
)


class MarkdownLinkTests(unittest.TestCase):
    def test_repository_discovery_includes_unignored_candidates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / ".gitignore").write_text("ignored.md\n", encoding="utf-8")
            (root / "tracked.md").write_text("# Tracked\n", encoding="utf-8")
            (root / "candidate.md").write_text("# Candidate\n", encoding="utf-8")
            (root / "ignored.md").write_text("# Ignored\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", ".gitignore", "tracked.md"],
                cwd=root,
                check=True,
            )

            files = repository_markdown_files(root)

        self.assertEqual(
            {"candidate.md", "tracked.md"},
            {path.name for path in files},
        )

    def test_repository_discovery_rejects_escape_and_missing_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            results = (
                (
                    subprocess.CompletedProcess([], 0, stdout=b"../escape.md\0"),
                    "escapes root",
                ),
                (
                    subprocess.CompletedProcess([], 0, stdout=b"missing.md\0"),
                    "is missing",
                ),
            )
            for result, message in results:
                with (
                    self.subTest(message=message),
                    patch(
                        "tools.check_markdown_links.subprocess.run",
                        return_value=result,
                    ),
                    self.assertRaisesRegex(RuntimeError, message),
                ):
                    repository_markdown_files(root)

    def test_extracts_commonmark_table_reference_and_image_links(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            markdown = root / "README.md"
            markdown.write_text(
                "# Overview\n\n"
                "[Guide][guide]\n\n"
                "| Asset |\n"
                "| --- |\n"
                "| ![Preview](preview.svg) |\n\n"
                "[guide]: docs/guide.md#setup\n",
                encoding="utf-8",
            )

            references = extract_markdown_links(root, (markdown,))

        self.assertEqual(
            [("docs/guide.md#setup", "link"), ("preview.svg", "image")],
            [(reference.target, reference.kind) for reference in references],
        )

    def test_extraction_rejects_markdown_outside_repository(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            parent = Path(tmpdir).resolve()
            root = parent / "repository"
            root.mkdir()
            outside = parent / "outside.md"
            outside.write_text("[Link](target.md)\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "escapes repository"):
                extract_markdown_links(root, (outside,))

    def test_validates_existing_files_exact_case_and_markdown_anchors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            docs = root / "docs"
            docs.mkdir()
            guide = docs / "Guide.md"
            guide.write_text("# Guide\n\n## Setup & Usage\n", encoding="utf-8")
            readme = root / "README.md"
            readme.write_text(
                "# Overview\n\n"
                "[Guide](docs/Guide.md#setup--usage)\n"
                "[Self](#overview)\n",
                encoding="utf-8",
            )
            references = extract_markdown_links(root, (readme, guide))

            issues = validate_internal_links(root, references)

        self.assertEqual((), issues)

    def test_rejects_missing_case_mismatched_escape_and_missing_anchor_targets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            docs = root / "docs"
            docs.mkdir()
            guide = docs / "Guide.md"
            guide.write_text("# Guide\n", encoding="utf-8")
            readme = root / "README.md"
            readme.write_text(
                "# Overview\n\n"
                "[Missing](docs/missing.md)\n"
                "[Case](docs/guide.md)\n"
                "[Escape](../outside.md)\n"
                "[Anchor](docs/Guide.md#missing)\n",
                encoding="utf-8",
            )
            references = extract_markdown_links(root, (readme, guide))

            issues = validate_internal_links(root, references)

        messages = {issue.message for issue in issues}
        self.assertEqual(4, len(issues))
        self.assertIn("target file does not exist", messages)
        self.assertIn("target path has incorrect letter case", messages)
        self.assertIn("path escapes repository root", messages)
        self.assertIn("Markdown anchor does not exist: #missing", messages)

    def test_internal_validation_handles_external_mailto_absolute_and_invalid_targets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            source = root / "README.md"
            source.write_text("# Overview\n", encoding="utf-8")
            asset = root / "evidence.txt"
            asset.write_text("evidence\n", encoding="utf-8")
            references = (
                LinkReference(source, 1, "//example.com/reference", "link"),
                LinkReference(source, 2, "https://example.com/reference", "link"),
                LinkReference(source, 3, "mailto:owner@example.com", "link"),
                LinkReference(source, 4, "/absolute/path.md", "link"),
                LinkReference(source, 5, "https://[invalid", "link"),
                LinkReference(source, 6, "evidence.txt#opaque-fragment", "link"),
            )

            issues = validate_internal_links(root, references)

        self.assertEqual(2, len(issues))
        self.assertEqual(
            {"repository-local path must be relative", "invalid URI: Invalid IPv6 URL"},
            {issue.message for issue in issues},
        )

    def test_internal_validation_fails_closed_when_directory_case_cannot_be_read(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            source = root / "README.md"
            source.write_text("# Overview\n", encoding="utf-8")
            reference = LinkReference(source, 1, "README.md", "link")

            with patch("tools.check_markdown_links.Path.iterdir", side_effect=OSError):
                issues = validate_internal_links(root, (reference,))

        self.assertEqual("target path has incorrect letter case", issues[0].message)

    def test_rejects_unsafe_uri_schemes_and_invalid_mailto_links(self):
        root = Path("/tmp").resolve()
        source = root / "README.md"
        references = (
            LinkReference(source, 1, "javascript:alert(1)", "link"),
            LinkReference(source, 2, "mailto:not-an-address", "link"),
        )

        issues = validate_internal_links(root, references)

        self.assertEqual(
            {"unsupported URI scheme: javascript", "invalid mailto address"},
            {issue.message for issue in issues},
        )

    def test_github_style_anchors_are_deterministic_for_duplicates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "README.md"
            path.write_text(
                "# Design & Scope\n\n"
                "## Result\n\n"
                "## Result\n\n"
                "## Result-1\n\n"
                "## Result\n",
                encoding="utf-8",
            )

            anchors = markdown_anchors(path)

        self.assertEqual("design--scope", _github_slug("Design & Scope"))
        self.assertEqual(
            frozenset(
                {
                    "design--scope",
                    "result",
                    "result-1",
                    "result-1-1",
                    "result-2",
                }
            ),
            anchors,
        )

    def test_external_targets_are_deduplicated_without_fragments(self):
        source = Path("/tmp/README.md")
        references = (
            LinkReference(source, 1, "https://example.com/page#one", "link"),
            LinkReference(source, 2, "https://example.com/page#two", "link"),
            LinkReference(source, 3, "//example.com/page", "image"),
            LinkReference(source, 4, "mailto:owner@example.com", "link"),
            LinkReference(source, 5, "https://[invalid", "link"),
        )

        targets = external_targets(references)

        self.assertEqual(("https://example.com/page",), tuple(targets))
        self.assertEqual(3, len(targets["https://example.com/page"]))

    def test_external_validation_reports_one_issue_per_unique_url(self):
        source = Path("/tmp/README.md")
        references = (
            LinkReference(source, 1, "https://example.com/broken#one", "link"),
            LinkReference(source, 2, "https://example.com/broken#two", "link"),
        )
        probed: list[str] = []

        def fake_probe(url: str, timeout: float, retries: int) -> ExternalProbe:
            probed.append(url)
            self.assertEqual(15.0, timeout)
            self.assertEqual(2, retries)
            return ExternalProbe(url, 404, url, "HTTP 404")

        issues, checked_count = validate_external_links(
            references,
            probe=fake_probe,
        )

        self.assertEqual(["https://example.com/broken"], probed)
        self.assertEqual(1, checked_count)
        self.assertEqual(1, len(issues))
        self.assertIn("2 references use this URL", issues[0].message)

    def test_external_validation_accepts_success_and_contains_probe_exceptions(self):
        source = Path("/tmp/README.md")
        references = (
            LinkReference(source, 1, "https://example.com/good", "link"),
            LinkReference(source, 2, "https://example.org/error", "link"),
        )

        def fake_probe(url: str, timeout: float, retries: int) -> ExternalProbe:
            if url.endswith("/good"):
                return ExternalProbe(url, 200, url, None)
            raise RuntimeError("probe failed")

        issues, checked_count = validate_external_links(
            references,
            workers=2,
            probe=fake_probe,
        )

        self.assertEqual(2, checked_count)
        self.assertEqual(1, len(issues))
        self.assertIn("RuntimeError: probe failed", issues[0].message)

    def test_external_validation_rejects_nonpositive_concurrency(self):
        for workers, per_host in ((0, 1), (1, 0)):
            with (
                self.subTest(workers=workers, per_host=per_host),
                self.assertRaisesRegex(ValueError, "must be positive"),
            ):
                validate_external_links((), workers=workers, per_host=per_host)

    def test_private_or_non_default_external_targets_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "only HTTP and HTTPS"):
            _validate_public_url("ftp://example.com/resource")
        with self.assertRaisesRegex(ValueError, "credentials"):
            _validate_public_url("https://user:secret@example.com/resource")
        with self.assertRaisesRegex(ValueError, "no hostname"):
            _validate_public_url("https:///resource")
        with self.assertRaisesRegex(ValueError, "invalid port"):
            _validate_public_url("https://example.com:not-a-port/resource")
        with self.assertRaisesRegex(ValueError, "non-public address"):
            _validate_public_url("http://127.0.0.1/resource")
        with self.assertRaisesRegex(ValueError, "non-default network port"):
            _validate_public_url("https://example.com:8443/resource")

    def test_dns_resolution_errors_and_empty_results_are_rejected(self):
        with (
            patch(
                "tools.check_markdown_links.socket.getaddrinfo",
                side_effect=OSError("resolver unavailable"),
            ),
            self.assertRaisesRegex(URLError, "hostname resolution failed"),
        ):
            _validate_public_url("https://example.com/resource")
        with (
            patch(
                "tools.check_markdown_links.socket.getaddrinfo",
                return_value=[],
            ),
            self.assertRaisesRegex(URLError, "did not resolve"),
        ):
            _validate_public_url("https://example.com/resource")

    def test_public_dns_resolution_is_accepted(self):
        public_result = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            )
        ]
        with patch(
            "tools.check_markdown_links.socket.getaddrinfo",
            return_value=public_result,
        ):
            _validate_public_url("https://example.com/resource")

    def test_redirect_handler_disables_automatic_redirects(self):
        handler = _NoRedirectHandler()

        result = handler.redirect_request(
            MagicMock(),
            MagicMock(),
            302,
            "Found",
            MagicMock(),
            "https://example.com/next",
        )

        self.assertIsNone(result)

    def test_external_request_follows_validated_redirect_and_reads_one_byte(self):
        start_url = "https://example.com/start"
        final_url = "https://example.com/next"
        redirect = HTTPError(
            start_url,
            302,
            "Found",
            {"Location": "/next"},
            io.BytesIO(),
        )
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 206
        response.geturl.return_value = final_url
        opener = MagicMock()
        opener.open.side_effect = [redirect, response]

        with (
            patch("tools.check_markdown_links.build_opener", return_value=opener),
            patch("tools.check_markdown_links._validate_public_url") as validate,
        ):
            status, observed_final_url = _request_external_url(start_url, 3.0)

        self.assertEqual((206, final_url), (status, observed_final_url))
        self.assertEqual([call(start_url), call(final_url)], validate.call_args_list)
        response.read.assert_called_once_with(1)
        request = opener.open.call_args.args[0]
        self.assertEqual("bytes=0-0", request.get_header("Range"))

    def test_external_request_returns_nonredirect_status_and_bounds_redirects(self):
        url = "https://example.com/start"
        not_found = HTTPError(url, 404, "Not Found", {}, io.BytesIO())
        opener = MagicMock()
        opener.open.side_effect = not_found
        with (
            patch("tools.check_markdown_links.build_opener", return_value=opener),
            patch("tools.check_markdown_links._validate_public_url"),
        ):
            self.assertEqual((404, url), _request_external_url(url, 3.0))

        redirects = [
            HTTPError(url, 302, "Found", {"Location": "/again"}, io.BytesIO())
            for _ in range(2)
        ]
        opener = MagicMock()
        opener.open.side_effect = redirects
        with (
            patch("tools.check_markdown_links.MAX_REDIRECTS", 1),
            patch("tools.check_markdown_links.build_opener", return_value=opener),
            patch("tools.check_markdown_links._validate_public_url"),
            self.assertRaisesRegex(ValueError, "redirect limit exceeded"),
        ):
            _request_external_url(url, 3.0)

    def test_transient_network_errors_are_retried(self):
        url = "https://example.com/resource"
        with (
            patch(
                "tools.check_markdown_links._request_external_url",
                side_effect=[URLError("temporary DNS failure"), (200, url)],
            ) as request,
            patch("tools.check_markdown_links.time.sleep") as sleep,
        ):
            result = probe_external_url(url, retries=2)

        self.assertTrue(result.passed)
        self.assertEqual(2, request.call_count)
        sleep.assert_called_once_with(0.5)

    def test_probe_retries_transient_http_and_stops_on_permanent_or_unsafe_errors(self):
        url = "https://example.com/resource"
        with (
            patch(
                "tools.check_markdown_links._request_external_url",
                side_effect=[(503, url), (200, url)],
            ) as request,
            patch("tools.check_markdown_links.time.sleep") as sleep,
        ):
            recovered = probe_external_url(url, retries=2)

        self.assertTrue(recovered.passed)
        self.assertEqual(2, request.call_count)
        sleep.assert_called_once_with(0.5)

        with patch(
            "tools.check_markdown_links._request_external_url",
            return_value=(404, url),
        ) as request:
            permanent = probe_external_url(url, retries=2)
        self.assertEqual("HTTP 404", permanent.error)
        request.assert_called_once()

        with patch(
            "tools.check_markdown_links._request_external_url",
            side_effect=ValueError("unsafe redirect"),
        ):
            unsafe = probe_external_url(url)
        self.assertEqual("unsafe redirect", unsafe.error)

        with self.assertRaisesRegex(ValueError, "zero or greater"):
            probe_external_url(url, retries=-1)

    def test_main_reports_internal_and_external_success_and_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            readme = root / "README.md"
            readme.write_text(
                "# Overview\n\n[Self](#overview)\n[Reference](https://example.com)\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                internal_status = main(["internal", "--root", str(root)])
            self.assertEqual(0, internal_status)
            self.assertIn("Internal links: 1 references passed", stdout.getvalue())

            readme.write_text("[Missing](missing.md)\n", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                internal_status = main(["internal", "--root", str(root)])
            self.assertEqual(1, internal_status)
            self.assertIn("target file does not exist", stderr.getvalue())

            readme.write_text("[Reference](https://example.com)\n", encoding="utf-8")
            stdout = io.StringIO()
            with (
                patch(
                    "tools.check_markdown_links.validate_external_links",
                    return_value=((), 1),
                ),
                redirect_stdout(stdout),
            ):
                external_status = main(["external", "--root", str(root)])
            self.assertEqual(0, external_status)
            self.assertIn("External links: 1 unique URLs passed", stdout.getvalue())

            issue = LinkIssue(
                readme,
                1,
                "https://example.com",
                "HTTP 503",
            )
            stderr = io.StringIO()
            with (
                patch(
                    "tools.check_markdown_links.validate_external_links",
                    return_value=((issue,), 1),
                ),
                redirect_stderr(stderr),
            ):
                external_status = main(["external", "--root", str(root)])
            self.assertEqual(1, external_status)
            self.assertIn("HTTP 503", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
