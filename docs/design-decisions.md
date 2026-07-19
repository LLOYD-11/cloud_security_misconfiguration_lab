# Design Decisions

This document records the architectural choices that shape version 2.0.0.
Each decision is accepted for the current project scope and includes the
tradeoffs a future maintainer should understand before changing it.

## DD-001: Analyze Exported Evidence Offline

**Status:** Accepted

**Decision:** The runtime consumes files and never authenticates to AWS or
changes cloud resources.

**Why:** Offline analysis avoids credential handling, accidental changes,
unbounded collection scope, and cloud charges. It also makes the sample
pipeline reproducible for students, reviewers, and CI.

**Consequences:** Evidence collection remains a separate authorized activity.
The lab cannot prove freshness, account-wide coverage, or live state. Native
adapters therefore reject known truncation and incomplete collection patterns.

**Alternative not chosen:** A live boto3 collector would improve convenience
but add credentials, permissions, pagination, network failures, and account
safety to the trusted runtime.

## DD-002: Normalize Native Exports Before Detection

**Status:** Accepted

**Decision:** AWS-shaped adapters translate supported exports into canonical
IAM, storage, network, and CloudTrail environments. Analyzers operate on those
canonical structures.

**Why:** Detection rules should not duplicate AWS response parsing or depend on
one collection representation. Simplified fixtures and native exports can
exercise the same rule logic.

**Consequences:** Normalizers must preserve security-relevant context instead
of flattening it away. A contract change may require adapter and analyzer
updates, but AWS-shape churn remains outside detector code.

**Alternative not chosen:** Running rules directly over each native API shape
would couple detection to collection details and create separate behavior for
sample and native inputs.

## DD-003: Use Shared, Versioned Result Models

**Status:** Accepted

**Decision:** All analyzers emit the same `Finding` model. Coverage, incidents,
rules, remediation plans, and timelines use separate versioned models and JSON
Schemas.

**Why:** Shared artifacts make report assembly module-neutral and give
reviewers explicit machine-readable contracts. Version checks prevent silent
interpretation of incompatible files.

**Consequences:** Producers and consumers must evolve contracts intentionally.
Python model validation supplements JSON Schema for cross-field invariants.
New writers emit findings v2 with stable identity and provenance. Readers accept
versioned v1 and v2 files, migrating unavailable v1 provenance to explicit
unknown values. Unversioned finding lists remain rejected.

**Alternative not chosen:** Ad hoc per-module JSON would reduce initial code
but force the report generator to understand every analyzer's internals.

## DD-004: Separate Detection, Correlation, and Presentation

**Status:** Accepted

**Decision:** Analyzers create findings, CloudTrail correlation creates
incidents, and the report layer derives timeline and remediation views.

**Why:** A rule match, a correlated triage lead, and a presentation narrative
make different claims. Keeping them separate preserves the original evidence
and lets each layer use an appropriate confidence model.

**Consequences:** The pipeline produces several artifacts rather than one
opaque result. Report inputs are cross-checked so mismatched artifacts fail
instead of being combined silently.

**Alternative not chosen:** Emitting only incidents or a final report would
discard reusable finding evidence and make correlation behavior difficult to
test independently.

## DD-005: Prefer Conservative Evidence Joins

**Status:** Accepted

**Decision:** Incident grouping uses normalized actor, source, and a bounded
window. Event IDs de-duplicate and qualify the group and contribute to its
stable ID. Timeline and remediation incident context require exact rule,
resource, and event-ID agreement.

**Why:** A portfolio security tool should avoid manufacturing attack chains
from title similarity or chronological proximity. Exact keys make every link
explainable.

**Consequences:** The model can miss relationships that require session,
account, topology, or semantic context. Documentation presents correlation as
a triage lead, not proof of compromise.

**Alternative not chosen:** Fuzzy or score-based joins could create richer
stories but would be harder to defend and more likely to overstate evidence.

## DD-006: Make Outputs Deterministic

**Status:** Accepted

**Decision:** Artifacts use stable sorting, canonical hashing for derived IDs,
explicit analysis parameters, and no implicit runtime timestamps. Finding IDs
include rule, resource, account, Region, observation time, and structured source
references, but exclude descriptive text and presentation metadata.

**Why:** Deterministic output enables byte-for-byte CI checks, meaningful
reviews, repeatable demonstrations, and stable references between artifacts.

**Consequences:** Callers must provide dates such as credential `as_of` and
sample report date when time affects a result. IDs change when material evidence
changes.

**Alternative not chosen:** Random UUIDs and generation timestamps would be
convenient but produce noisy diffs and weaken reproducibility.

## DD-007: Publish Confidence and Mapping Qualifications

**Status:** Accepted

**Decision:** The rule catalog records evidence-to-rule confidence and labels
framework mappings as `direct` or `related`. Built-in analyzers copy that
confidence into each v2 finding so downstream artifacts retain the claim even
when the catalog is not present.

**Why:** A detector match is not the same as malicious intent, and a related
MITRE or control reference is not certification. Qualified mappings make those
boundaries visible.

**Consequences:** Catalog maintenance requires authoritative references and
careful rationale. Reports reject a known finding whose non-unknown confidence
disagrees with the catalog. Unknown custom rules remain report-compatible but
receive no automatic mapping or confidence claim.

**Alternative not chosen:** Unqualified framework labels would look broader but
risk implying complete control coverage.

## DD-008: Use Explainable Priority Bands

**Status:** Accepted

**Decision:** Remediation uses published P0-P3 rules and keeps incident response
separate from permanent configuration work.

**Why:** The available evidence does not support a mathematically defensible
breach-probability or business-impact score. Priority bands can state exactly
why a work item is urgent.

**Consequences:** Asset value, ownership, effort, dependencies, compensating
controls, and change windows remain analyst inputs. The plan is a triage queue,
not an autonomous change plan.

**Alternative not chosen:** A weighted numeric score would create false
precision unless the project collected substantially more business context.

## DD-009: Keep the Runtime Dependency-Free

**Status:** Accepted

**Decision:** Runtime parsing, analysis, correlation, and reporting use the
Python standard library. Development tools remain optional dependencies.

**Why:** A dependency-free runtime is easy to inspect, install, and run in
restricted teaching or review environments. It also reduces supply-chain and
versioning surface for a small offline tool.

**Consequences:** Full JSON Schema validation belongs to development and CI.
The shared `cloud_inputs` boundary performs focused, path-aware runtime
validation for every simplified field consumed by an analyzer without
reimplementing the complete JSON Schema standard. A proven library should still
be adopted if future scope makes a standard-library implementation less safe or
maintainable.

**Alternative not chosen:** Making boto3, pydantic, or a policy engine mandatory
would add capabilities but also substantial runtime weight not required by the
current scope.

## DD-010: Preserve Compatibility at the Edges

**Status:** Accepted

**Decision:** The unified CLI is the primary interface, while original analyzer
scripts, versioned findings v1 files, and uncataloged custom findings remain
supported where their contracts are explicit.

**Why:** Version 2 adds engineering structure without making the original lab
workflows unusable. Compatibility tests make that promise executable.

**Consequences:** Some wrapper code remains. Compatibility does not extend to
ambiguous unversioned result files, because silently guessing their meaning
would weaken report integrity.

**Alternative not chosen:** Removing legacy entry points would simplify the
tree but create unnecessary migration cost for existing users and examples.

## DD-011: Lock Executable Development Inputs

**Status:** Accepted

**Decision:** CI and release workflows pin each external action to a verified
full commit SHA. Direct and transitive development packages, including the
setuptools build backend, are installed from one universal requirements file
with exact versions and SHA-256 hashes.

**Why:** Broad dependency ranges remain useful declarations for maintainers,
but resolving them during every CI run permits behavior to change without a
repository diff. Mutable action tags can move independently of this project.

**Consequences:** Dependency upgrades are explicit review events. Editable
installs use `--no-build-isolation --no-deps`, release builds use
`--no-isolation`, and lock regeneration records the exact resolver version.
Python patch releases and the Ubuntu 24.04 hosted image continue to receive
upstream security updates and are not claimed to be bit-for-bit fixed machines.

**Alternative not chosen:** Floating action tags and `pip install -e ".[dev]"`
are easier to maintain but execute newly resolved third-party code without a
corresponding project change.

## DD-012: Gate Public Documentation as Executable Evidence

**Status:** Accepted

**Decision:** CI exercises every declared Python minor and, once per run,
validates all tracked Markdown with a locked linter, parser-based internal link
checks, and bounded external HTTP probes. The release workflow repeats all
three documentation gates.

**Why:** Documentation is part of the review surface for this project. A stale
compatibility claim, missing local artifact, malformed Markdown file, or dead
framework reference can invalidate otherwise correct implementation evidence.

**Consequences:** Internal checks are deterministic and enforce repository
containment, exact path case, and GitHub-style heading anchors. External checks
depend on upstream availability, so they deduplicate targets, limit per-host
concurrency, and retry only transient failures. Network probes reject
credentials, non-default ports, and hosts resolving to non-public addresses.

**Alternative not chosen:** Manual link review avoids network-sensitive CI but
does not prevent documentation regressions and is difficult to reproduce during
admissions or engineering review.

## DD-013: Separate Signed Build Evidence from Release Authority

**Status:** Accepted

**Decision:** A low-privilege release job builds and tests the distributions,
inventories an isolated wheel installation as SPDX 2.3, writes an exact
SHA-256 manifest, and signs both build provenance and an SBOM predicate. It
verifies the signer workflow before transferring the candidate. A separate job
with release-write permission rechecks the transferred hashes and attestations,
does not check out repository source, and publishes only explicit asset types.

**Why:** Checksums without authenticated origin can be replaced together with
an artifact. An SBOM that scans only opaque archives can miss the Python
package. Giving build scripts the same token that publishes releases also
unnecessarily combines code execution and repository-write authority.

**Consequences:** Starting with `v2.2.0`, releases include the wheel, source
distribution, SPDX inventory, `SHA256SUMS`, SLSA provenance bundle, and SPDX
attestation bundle. The verifier rejects stale or duplicate distributions,
symlinks, unsafe manifest names, wrong package identity, incomplete SPDX
inventory, and digest mismatches. The release depends on GitHub OIDC, Sigstore,
Syft, and immutable workflow-artifact transfer and does not claim a hermetic
build or a particular SLSA level.

**Alternative not chosen:** A single write-enabled job is shorter, and a bare
checksum file is familiar, but neither provides the same authority separation
or independently verifiable builder identity.

## Revisit Triggers

These decisions should be revisited if the project adds:

- A live, authorized collection service
- Multi-account or organization-wide analysis
- A proven IAM policy-evaluation engine
- Raw AWS reachability-analysis parsing
- Persistent case management or analyst collaboration
- Business-criticality, ownership, and remediation-workflow data

Those capabilities would change trust boundaries and may justify new
dependencies, storage, APIs, or deployment architecture.
