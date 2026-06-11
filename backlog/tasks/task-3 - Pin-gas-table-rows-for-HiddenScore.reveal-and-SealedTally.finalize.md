---
id: TASK-3
title: Pin gas-table rows for HiddenScore.reveal() and SealedTally.finalize()
status: Done
assignee: []
created_date: '2026-06-11 05:07'
updated_date: '2026-06-11 06:01'
labels:
  - audit
  - roborev-confirmed
dependencies: []
references:
  - README.md
  - test/HiddenScore.t.sol
  - test/SealedTally.t.sol
priority: low
ordinal: 3000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Source: roborev compact consolidation job 6999 (codex, Low), re-verified against current code.

README gas table (around README.md:118) publishes HiddenScore.reveal() ~32K and SealedTally.finalize() k=3 ~41K, but committed gas probes cover only credit(), ctAdd, and innerProduct32 — so those two rows can silently drift. Overlaps TASK-1 AC#7 (this task supersedes/satisfies it).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Add gas tests for HiddenScore.reveal() and SealedTally.finalize(), OR mark those README rows as point-in-time estimates not pinned by tests
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Done together with TASK-1 AC#7: added test_reveal_gas / test_finalize_gas probes and annotated README rows as point-in-time full-tx estimates.
<!-- SECTION:NOTES:END -->
