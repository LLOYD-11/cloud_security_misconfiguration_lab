# CloudTrail Failure-Window Performance

Rule `CLD-006` aggregates failed AWS API calls for the same account, actor, and
source when a configurable threshold is reached inside a bounded time window.
This document records the algorithmic contract and regression evidence for that
window search.

## Behavioral Contract

The optimized detector preserves these observable behaviors:

- Failed events are grouped by account ID, actor, and source IP.
- Each group is placed in stable UTC timestamp order; equal timestamps retain
  input order.
- The first anchor whose inclusive window reaches the threshold is selected.
- An event exactly on the right boundary is included.
- The finding contains every failure inside the selected anchor's maximal
  window, not only the minimum number needed to reach the threshold.
- At most one `CLD-006` finding is emitted for each group.
- Finding IDs, evidence references, timestamps, metadata, and ordering remain
  deterministic.

## Complexity

Let `F` be the number of failed events and `n_g` the number in group `g`.

The earlier implementation sorted each group and then rebuilt the remaining
suffix for every possible anchor. Its post-sort search cost was
`O(sum(n_g^2))` in the worst case.

The current implementation parses each failed-event timestamp once, retains the
existing `O(sum(n_g log n_g))` group sorting cost, and advances a monotonic
right pointer through each group. Each edge moves at most once, so the
post-sort window search is `O(F)`. The complete rule is therefore
`O(F + sum(n_g log n_g))` time and `O(F)` auxiliary memory.

## Regression Evidence

The CloudTrail test suite uses three complementary checks:

1. A frozen copy of the previous quadratic implementation acts as a behavioral
   oracle. The optimized detector must produce exactly equal `Finding` objects
   for a deterministic corpus of 2,880 events across 80 groups, two accounts,
   and two Regions under five threshold and window configurations. The corpus
   contains 2,400 failures and 480 successful baseline events.
2. Boundary cases prove inclusive right-edge behavior and selection of the
   first qualifying anchor.
3. A 10,000-point no-match case instruments timestamp subtraction operations
   and enforces a structural upper bound of `2F`. This verifies pointer
   monotonicity without using a hardware-dependent wall-clock assertion.

Run the focused evidence with:

```bash
python3 -m unittest cloudtrail_detector.test_detector
```

These checks establish the M6 algorithmic requirement. Repeatable runtime and
memory corpora, acceptance budgets, and broader fault-tolerance evidence belong
to M8 and are tracked separately in the upgrade roadmap.
