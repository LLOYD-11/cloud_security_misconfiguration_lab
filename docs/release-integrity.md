# Release Integrity

Starting with `v2.2.0`, the tag-triggered release workflow is designed to
publish the distributions and their independently verifiable integrity
evidence. The implementation can be reviewed before that tag exists; no
checksum, SBOM, or attestation asset should be inferred for an older release.

## Published Assets

| Asset | Purpose |
| --- | --- |
| `cloud_security_misconfiguration_lab-<version>-py3-none-any.whl` | Installed Python distribution |
| `cloud_security_misconfiguration_lab-<version>.tar.gz` | Source distribution |
| `cloud-security-misconfiguration-lab.spdx.json` | Syft SPDX 2.3 inventory of the installed wheel payload |
| `SHA256SUMS` | SHA-256 values for the wheel, source distribution, and SBOM |
| `cloud-security-misconfiguration-lab-build-provenance.sigstore.json` | Signed SLSA provenance bundle for both distributions, the SBOM, and `SHA256SUMS` |
| `cloud-security-misconfiguration-lab-sbom-attestation.sigstore.json` | Signed SPDX predicate binding the SBOM to the wheel |

The checksum manifest excludes the two attestation bundles because each bundle
contains its own signed verification material and is produced only after the
manifest is complete. Checksums detect accidental or malicious content changes;
the Sigstore attestations establish the GitHub repository and workflow that
signed the artifact.

## Generation and Enforcement

The release uses Syft `v1.48.0` through an immutable
`anchore/sbom-action` revision. It scans an isolated installation of the wheel,
not the `dist` directory, because scanning archive files as an opaque directory
does not inventory the installed Python package. The source is explicitly
identified as `cloud-security-misconfiguration-lab-wheel@<version>` so the
document does not inherit a runner-specific directory identity.

`tools/release_evidence.py` then fails unless:

- exactly one regular, non-symlink wheel, source distribution, and SPDX JSON
  file exists;
- filenames identify the expected project and tag version;
- the bounded SPDX document is version 2.3 under `CC0-1.0`;
- the document describes the explicitly named wheel source at the tag version;
- exactly one project package has the expected version, MIT license, PyPI purl,
  analyzed-file inventory, package verification code, and a relationship path
  from the SPDX document;
- `SHA256SUMS` contains exactly those three basenames, without paths or
  duplicates; and
- every streamed SHA-256 digest matches.

GitHub's `actions/attest` signs default SLSA provenance for the release assets
and a separate SPDX predicate for the wheel. The workflow immediately verifies
the generated bundles while still in the low-privilege job, transfers the
candidate through an immutable workflow artifact, and repeats checksum and
signature verification in the isolated publisher job.

## Verify Checksums

Download all assets from the selected release into one directory. On Linux:

```bash
sha256sum --check SHA256SUMS
```

On macOS:

```bash
shasum -a 256 -c SHA256SUMS
```

All three listed files must report `OK`. This proves agreement with the
downloaded manifest, not who created that manifest. Verify provenance next.

## Verify Build Provenance

Install a current [GitHub CLI](https://cli.github.com/) and run this for the
wheel, source distribution, SBOM, or `SHA256SUMS`:

```bash
gh attestation verify <artifact> \
  --repo LLOYD-11/cloud_security_misconfiguration_lab \
  --bundle cloud-security-misconfiguration-lab-build-provenance.sigstore.json \
  --signer-workflow \
  LLOYD-11/cloud_security_misconfiguration_lab/.github/workflows/release.yml
```

Verification checks the artifact digest, Sigstore signature, GitHub repository,
OIDC identity, SLSA predicate type, and exact signer-workflow path.

## Verify the SBOM Attestation

Run this against the wheel:

```bash
gh attestation verify <wheel-file> \
  --repo LLOYD-11/cloud_security_misconfiguration_lab \
  --bundle cloud-security-misconfiguration-lab-sbom-attestation.sigstore.json \
  --predicate-type https://spdx.dev/Document/v2.3 \
  --signer-workflow \
  LLOYD-11/cloud_security_misconfiguration_lab/.github/workflows/release.yml
```

The standalone SPDX file remains human- and tool-readable. From a matching
source checkout, its package identity and checksum set can also be rechecked:

```bash
python -m tools.release_evidence verify \
  --dist <download-directory> \
  --project-name cloud-security-misconfiguration-lab \
  --version <version-without-v> \
  --license-id MIT
```

## Online and Offline Boundaries

The bundle option avoids fetching the attestation from the GitHub API, but
normal verification still refreshes Sigstore trusted-root material. For an
air-gapped review, obtain current trusted roots while online with
`gh attestation trusted-root`, transfer them with the artifacts and bundles,
and add `--custom-trusted-root <trusted-root-file>`. Trusted roots can later be
revoked or rotated, so stale root material carries additional residual risk.

The evidence proves artifact digest, signer identity, predicate type, and
workflow provenance. It does not prove that the source code is vulnerability
free, that all upstream infrastructure is uncompromised, or that separate
builds are byte-for-byte identical.

## References

- [GitHub artifact-attestation verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [Offline attestation verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)
- [`actions/attest`](https://github.com/actions/attest)
- [Anchore SBOM Action](https://github.com/anchore/sbom-action)
- [Syft](https://github.com/anchore/syft)
- [SPDX 2.3 specification](https://spdx.github.io/spdx-spec/v2.3/)
