# Independent Evaluation Corpus

## Freeze Status

Corpus `1.0.0` was frozen on 2026-08-13 for the candidate at commit
`6d71c99914a38b6e161bc9cf56407eb1757b8c9a`. Its normative record is the
[`corpus-manifest-v1.0.json`](../evaluation/corpus-manifest-v1.0.json), bound to
the previously frozen [evaluation protocol](evaluation-protocol.md) by protocol
version and SHA-256 digest.

The corpus was authored, cited, reviewed, sanitized, hashed, and committed
without importing or executing a candidate analyzer. This is a procedural
holdout created by the project author, not third-party annotation or an
independent laboratory study. No accuracy, baseline-agreement, or release-pass
result is claimed at this stage.

## Inventory

The corpus contains 32 cases and 42 retained files. Each module has exactly two
positive, two hardened-negative, two boundary, and two ambiguous cases.

| Module | Cases | Files | Positive | Negative | Ambiguous | Native/Simplified Pairs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| IAM | 8 | 12 | 31 | 30 | 2 | 2 |
| Storage | 8 | 10 | 15 | 21 | 2 | 2 |
| Network | 8 | 10 | 8 | 10 | 2 | 2 |
| CloudTrail | 8 | 10 | 24 | 29 | 2 | 2 |
| **Total** | **32** | **42** | **78** | **90** | **8** | **8** |

The 168 positive and negative assertions are scored. Eight ambiguous
assertions are preserved but excluded from classification metrics. All 35
registered rules have at least two positive and two negative assertions. One
assertion is one predeclared decision key:

```text
(case_id, rule_id, resource_type, resource_id)
```

The native/simplified equivalence pairs are `EVAL-IAM-001`, `EVAL-IAM-003`,
`EVAL-STO-001`, `EVAL-STO-003`, `EVAL-NET-001`, `EVAL-NET-003`,
`EVAL-CLD-001`, and `EVAL-CLD-003`. IAM native variants retain both an
authorization-details snapshot and a credential report; the other native
variants retain their module-specific AWS-shaped JSON evidence.

## Construction Controls

Evidence is independently authored synthetic data grounded in official AWS
semantics. Structural formats reuse the published input contracts, but case
identities, values, scenarios, combinations, and expected decisions do not
reuse project samples, benchmark expectations, analyzer tests, sample-report
findings, or candidate output.

Each case records:

- origin, retrieval date, authoritative references, and source locator;
- semantic transformations and sanitization actions;
- a primary annotation pass and a separate verification pass;
- explicit declarations that neither pass saw candidate output;
- every expected decision, severity, rationale, and exclusion; and
- each evidence path, media type, contract, byte size, and SHA-256 digest.

The fixtures use fictional accounts and resources, documentation or private IP
ranges, and no credentials, personal records, customer data, or organization
identifiers. Public CIDRs such as `0.0.0.0/0` and `::/0` are intentional rule
inputs rather than observed addresses.

## Candidate-Independent Verification

Install the locked development environment and run:

```bash
.venv/bin/python -m tools.evaluation_corpus
```

The verifier imports no candidate package. It validates:

- the corpus-manifest and every JSON evidence contract;
- the frozen protocol digest, candidate revision, and 35-rule inventory;
- exact case, assertion, class, and per-rule coverage minimums;
- unique case IDs, assertion IDs, decision keys, and declared file paths;
- complete native/simplified pair contracts and equivalence groups;
- output-blind review records, citation coverage, and freeze-date ordering;
- bounded regular files, exact sizes and hashes, safety patterns, and CSV
  headers; and
- exact corpus inventory with no symlinks, traversal, missing, duplicate, or
  undeclared files.

Adversarial tests prove that evidence, protocol, or rule-catalog digest
tampering, a hidden extra file, a duplicate decision key, reduced rule
coverage, a broken equivalence pair, output exposure, a local path in the
manifest, a falsely attributed AWS citation, a wrong module contract, and
symlinked evidence all fail closed.

This command only verifies the frozen inputs and labels. It does not feed the
corpus into an analyzer or reveal candidate performance.

## Interpretation Limits

- Both annotation passes were performed under procedural context separation by
  the project author. Personnel independence is not claimed.
- Synthetic cases improve safety and predicate control but cannot represent all
  organization policies, live topology, service interactions, or behavior.
- Two positive and two negative assertions per rule are enough for broad rule
  coverage, not narrow per-rule confidence intervals.
- Ambiguous decisions remain visible and excluded rather than being forced into
  whichever class benefits the candidate.
- AWS documentation can change after the recorded retrieval date.

M12-R3 may begin only after this corpus is committed and published. It will
freeze the exact Prowler and Sigma overlap matrix and baseline outcomes before
M12-R4 executes the candidate and publishes raw decisions, metrics,
disagreements, ablations, and acceptance checks.
