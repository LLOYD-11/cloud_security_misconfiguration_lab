# Markdown Report Integrity

The report generator treats text loaded from findings, incidents, analysis
summaries, remediation actions, timeline entries, and source paths as untrusted
artifact data. Those values must remain visible without being able to create
report headings, lists, tables, links, raw HTML, or code fences.

## Rendering Boundaries

The renderer applies an output rule for each Markdown context:

| Context | Rule |
| --- | --- |
| Prose and headings | Normalize line and control characters, escape inline Markdown delimiters, and encode angle brackets |
| Inline code | Normalize line and control characters and use a delimiter longer than every backtick run in the value |
| Table text | Apply prose escaping and encode pipe characters so values cannot create columns |
| Table inline code | Use the dynamic code delimiter and encode pipe characters |
| References | Preserve only conservative single-line HTTPS references; render every other value as inert escaped text |

Renderer-owned Markdown remains separate from artifact data. In particular,
remediation-plan rationales are plain text in JSON; the report layer alone owns
Markdown syntax.

## Security Property

For any model-valid artifact text:

- The report's expected heading hierarchy is unchanged.
- Outside the designated reference context, one artifact value cannot add a
  list item, blockquote, code fence, table column, raw HTML element, or active
  Markdown link.
- The original text remains reviewable in a single line or a safely delimited
  code span.
- Ordinary HTTPS references remain usable.

This boundary protects report structure. It does not establish that a finding
is correct, that a reference is trustworthy, or that a downstream non-Markdown
conversion tool is free of its own vulnerabilities.

## Regression Evidence

The report tests use one adversarial corpus across finding, incident, summary,
timeline, remediation, metadata, evidence-reference, and source-path fields. It
includes CRLF, Unicode line separators, headings, lists, blockquotes, table
pipes, backslashes, raw HTML, links, emphasis, and multiple backtick-run
lengths. The test verifies the complete expected section hierarchy and table
boundaries rather than checking only one escaped substring.
