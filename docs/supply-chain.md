# Supply-Chain Controls

The runtime has no third-party dependencies. Development, CI, packaging, and
release tasks still execute external tools, so those inputs are versioned and
reviewed separately from the runtime design.

## Immutable Actions

GitHub recommends a full-length commit SHA as the only immutable way to consume
an action. Both workflows pin the following official releases:

| Action | Reviewed Release | Immutable Commit |
| --- | --- | --- |
| `actions/checkout` | `v7.0.0` | `9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0` |
| `actions/setup-python` | `v6.3.0` | `ece7cb06caefa5fff74198d8649806c4678c61a1` |
| `anchore/sbom-action` | `v0.24.0` | `e22c389904149dbc22b58101806040fa8d37a610` |
| `actions/attest` | `v4.2.0` | `f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6` |
| `actions/upload-artifact` | `v7.0.1` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| `actions/download-artifact` | `v8.0.1` | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |

The release tags and commits were verified through the official repositories on
2026-07-19. Version comments remain beside each SHA so automated and human
reviews can understand an update without weakening immutability.

References:

- [GitHub secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use#using-third-party-actions)
- [`actions/checkout` v7.0.0](https://github.com/actions/checkout/releases/tag/v7.0.0)
- [`actions/setup-python` v6.3.0](https://github.com/actions/setup-python/releases/tag/v6.3.0)
- [`anchore/sbom-action` v0.24.0](https://github.com/anchore/sbom-action/releases/tag/v0.24.0)
- [`actions/attest` v4.2.0](https://github.com/actions/attest/releases/tag/v4.2.0)
- [`actions/upload-artifact` v7.0.1](https://github.com/actions/upload-artifact/releases/tag/v7.0.1)
- [`actions/download-artifact` v8.0.1](https://github.com/actions/download-artifact/releases/tag/v8.0.1)

## Development Lock

`pyproject.toml` is the human-maintained declaration of compatible development
tool ranges. `requirements-dev.lock` is the executable environment:

- every direct and transitive package uses `==`;
- every applicable distribution has one or more reviewed SHA-256 hashes;
- environment markers preserve one lock across supported Python and operating
  system combinations;
- setuptools is included so editable installs and release builds do not resolve
  a separate build backend.

In universal mode, uv treats the current or explicitly supplied Python version
as the resolution's lower bound. The compile command therefore supplies
`--python-version 3.10`, matching the project's minimum supported version,
instead of depending on the maintainer's active interpreter.

Install it with pip's all-or-nothing hash-checking mode:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-dev.lock
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
.venv/bin/python -m pip check
```

CI uses the same commands. Distribution builds use
`.venv/bin/python -m build --no-isolation`.

References:

- [pip secure installs and hash-checking mode](https://pip.pypa.io/en/stable/topics/secure-installs/)
- [uv requirements locking](https://docs.astral.sh/uv/pip/compile/)
- [uv universal-resolution semantics](https://docs.astral.sh/uv/reference/cli/#uv-pip-compile)

## Reviewed Update Procedure

1. Review release notes for each direct development tool and build backend.
2. Install `uv==0.11.29` in an isolated environment.
3. Regenerate the universal lock:

   ```bash
   uv pip compile pyproject.toml --extra dev --universal \
     --python-version 3.10 \
     --generate-hashes --format requirements.txt \
     --output-file requirements-dev.lock
   ```

4. Review version, marker, dependency-origin, and hash changes in the lock.
5. Install the lock in a fresh virtual environment with `--require-hashes`, run
   `pip check`, and execute the complete local release gate.
6. For an Action update, verify the exact release tag through its official
   repository and replace both the full SHA and adjacent version comment.

## Enforced Invariants

`tests/test_supply_chain.py` rejects:

- any workflow `uses:` reference that is not a 40-character lowercase commit
  SHA with its reviewed release comment;
- missing hash-checked installation, disabled build isolation, lock-aware cache
  keys, or post-install `pip check` in either workflow;
- a development requirement that is absent from the lock;
- a lock entry without an exact version or a valid SHA-256 hash.
- persisted checkout credentials or unreviewed release-evidence Actions;
- release jobs that omit separate build, signing, transfer, and publish
  verification controls; and
- release workflows that omit the pinned Syft version, SPDX predicate,
  checksums, or exact signer-workflow verification.

## Release Authority Boundary

The release build job can read repository contents and request short-lived OIDC
and attestation credentials. It cannot create or modify a GitHub Release.
Checkout does not persist credentials in the working tree.

The publisher job can write repository release contents, but it receives only
the staged candidate, does not check out source, and does not execute project
Python. It rechecks the SHA-256 manifest and both Sigstore bundles after the
workflow-artifact transfer. This separation limits the authority available to
third-party build tooling and repository code.

See [Release integrity](release-integrity.md) for the artifact trust chain and
[Threat model](threat-model.md) for the remaining upstream dependencies.

## Residual Boundary

The lock constrains selected package versions and accepted distributions; it
does not make builds bit-for-bit reproducible. GitHub-hosted Ubuntu 24.04 images,
the latest patch release of each requested Python minor, pip itself, network
availability, and PyPI metadata remain upstream inputs. Release checksums, an
SBOM, and build provenance establish integrity and origin but do not make the
source vulnerability-free or the build environment hermetic. GitHub CLI and
Sigstore trusted-root freshness are also release-verification dependencies.
