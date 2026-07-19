# Documentation Quality Gates

Public documentation is treated as executable project evidence. The local and
CI gates cover every tracked or unignored candidate Markdown file rather than a
manually maintained subset.

## Markdown Lint

[PyMarkdown](https://pymarkdown.readthedocs.io/en/stable/) parses and scans the
documentation in read-only mode. Its configuration is committed in
`pyproject.toml` and loaded with `--strict-config` so misspelled or unsupported
settings fail instead of silently falling back.

GitHub-style tables are enabled. The project keeps all default rules except:

- `MD013` line length is disabled because rule tables, immutable hashes, URLs,
  and copyable commands contain intentional long lines.
- `MD024` permits repeated headings only below different parents, which allows
  standard `Added` and `Changed` changelog sections while still rejecting
  duplicate sibling headings.

## Internal Links

`tools/check_markdown_links.py` uses
[markdown-it-py](https://markdown-it-py.readthedocs.io/en/latest/using.html) in
CommonMark mode with table support. It resolves inline, reference-style, image,
and autolink targets from parser tokens rather than searching Markdown with a
regular expression.

The internal gate rejects:

- missing files and directory targets;
- paths that escape the repository or begin at an ambiguous filesystem root;
- letter-case mismatches that may work on macOS but fail on Linux or GitHub;
- unsupported URI schemes and malformed `mailto` targets;
- missing fragments in Markdown targets, using
  [GitHub heading-anchor rules](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax#section-links).

## External Links

External checks remove fragments and probe each unique HTTP resource once. A
small ranged `GET` is used because many documentation servers reject `HEAD`.
Success requires a final 2xx or 3xx response.

The checker bounds network behavior with:

- a 15-second request timeout, two retries, and exponential delay only for
  transient connection or HTTP failures;
- eight global workers, at most two requests per hostname, and eight redirects;
- HTTP and HTTPS only, with no embedded credentials or non-default ports;
- DNS checks that reject loopback, private, link-local, reserved, multicast, or
  otherwise non-public addresses before every request and redirect.

These controls make the checker appropriate for this repository's CI surface;
they do not turn it into a general-purpose network sandbox. DNS can change
between validation and connection, external fragments are not inspected, and
JavaScript-only destinations may require manual review. Upstream outages can
still fail the gate after retries and should be investigated before a rerun.

The checker is included in the project's measured branch coverage. Dedicated
tests exercise repository containment, exact-case paths, heading collisions,
DNS and URL rejection, redirect bounds, retry behavior, probe isolation, and
both CLI outcomes.

## Commands

Run from the repository root after installing `requirements-dev.lock`:

```bash
.venv/bin/pymarkdown --strict-config scan --respect-gitignore .
.venv/bin/python -m tools.check_markdown_links internal
.venv/bin/python -m tools.check_markdown_links external
```

CI runs the three checks once in the Python 3.13 matrix job. The release
workflow repeats them before building or publishing distributions.
