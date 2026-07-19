# Security Policy

## Supported Versions

Security fixes are applied to the latest tagged release and the default branch.
Older releases and development branches are not maintained security lines.

| Version | Security support |
| --- | --- |
| Latest tagged release | Supported |
| Default branch | Fixes in preparation |
| Older releases | Not supported |

## Report a Vulnerability

Use GitHub's private vulnerability reporting flow from the repository
`Security` tab when `Report a vulnerability` is available. This keeps the
report and any proof of concept out of public issues.

If private reporting is unavailable, open a public issue titled
`Private security contact requested`. Include no vulnerability details,
affected inputs, exploit steps, logs, or proof of concept. The maintainer will
establish a private channel before technical information is exchanged.

Please include privately:

- the affected release, commit, command, and input format;
- the expected security property and observed behavior;
- minimal reproduction steps using synthetic or sanitized evidence;
- impact, preconditions, and whether the issue is already public; and
- a suggested fix or test, when available.

Do not submit secrets, personal data, live credentials, or unsanitized cloud
evidence.

## Response Targets

These are best-effort targets rather than a service-level agreement:

- acknowledgement within seven days;
- an initial severity and scope assessment within 14 days;
- status updates when the assessment or fix materially changes; and
- coordinated disclosure after a fix or documented mitigation is available.

The project may request more information, reject reports outside the supported
boundary, or publish a security advisory when users need to take action.

## In Scope

- bypasses of documented byte, decompression, nesting, node, resource, or file
  limits;
- path traversal, unsafe symlink handling, or unintended local-file overwrite;
- malformed evidence that reaches analysis after a fail-closed validation
  boundary;
- report text that changes the fixed Markdown structure;
- unexpected network, AWS authentication, credential use, or cloud mutation by
  the runtime;
- a material detection or coverage bypass that creates false assurance within
  a documented rule;
- tampered release assets that pass the checksum, SBOM, or attestation gates;
  and
- exposure of secrets or personal data committed by this repository.

## Out of Scope

- unsupported AWS services, policy interactions, and evidence types already
  listed in [Known limitations](docs/known-limitations.md);
- claims based only on missing rules, expected false positives, or expected
  false negatives outside the published analyzer contracts;
- vulnerabilities in GitHub, AWS, Python, Syft, or another upstream service
  that do not arise from this repository's integration;
- denial of service that requires inputs above the documented resource limits;
  and
- social engineering, credential attacks, or testing against systems and data
  without explicit authorization.

## Good-Faith Research

Test only with systems, accounts, and evidence that you own or are explicitly
authorized to assess. Use the smallest synthetic reproduction possible, stop
if real data is exposed, and avoid privacy violations or service disruption.
This educational project does not operate a bug-bounty program or promise
payment.

The system boundary and residual risks are documented in the
[Threat model](docs/threat-model.md).

## References

- [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately)
- [Configuring private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository)
