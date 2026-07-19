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

The release tags and commits were verified through the official repositories on
2026-07-19. Version comments remain beside each SHA so automated and human
reviews can understand an update without weakening immutability.

References:

- [GitHub secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use#using-third-party-actions)
- [`actions/checkout` v7.0.0](https://github.com/actions/checkout/releases/tag/v7.0.0)
- [`actions/setup-python` v6.3.0](https://github.com/actions/setup-python/releases/tag/v6.3.0)

## Development Lock

`pyproject.toml` is the human-maintained declaration of compatible development
tool ranges. `requirements-dev.lock` is the executable environment:

- every direct and transitive package uses `==`;
- every applicable distribution has one or more reviewed SHA-256 hashes;
- environment markers preserve one lock across supported Python and operating
  system combinations;
- setuptools is included so editable installs and release builds do not resolve
  a separate build backend.

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

## Reviewed Update Procedure

1. Review release notes for each direct development tool and build backend.
2. Install `uv==0.11.29` in an isolated environment.
3. Regenerate the universal lock:

   ```bash
   uv pip compile pyproject.toml --extra dev --universal \
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

## Residual Boundary

The lock constrains selected package versions and accepted distributions; it
does not make builds bit-for-bit reproducible. GitHub-hosted Ubuntu 24.04 images,
the latest patch release of each requested Python minor, pip itself, network
availability, and PyPI metadata remain upstream inputs. Release checksums, an
SBOM, and build provenance are separate M11 controls.
