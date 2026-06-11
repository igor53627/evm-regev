---
id: TASK-2
title: >-
  SealedTally: no abort/timeout/reset — one faulty member permanently bricks the
  instance
status: To Do
assignee: []
created_date: '2026-06-11 05:07'
labels:
  - security
  - audit
  - roborev-confirmed
dependencies: []
references:
  - examples/SealedTally.sol
priority: medium
ordinal: 2000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Source: roborev compact consolidation job 6999 (codex, Medium), re-verified against current code.

The phase machine is strictly forward (Open -> Committing -> Revealing -> Finalized) with no timeout/abort/reset. After startReveal() freezes the snapshot, a committee member that never commits or never reveals (lost key, griefing, or a self-bricked slot via an out-of-range committed partial) leaves finalize() reverting forever; the frozen accumulator/snapshot cannot be re-run. README equates this to "multisig liveness", but a multisig can usually re-propose — here recovery requires redeploy + replay of all contributions.

This is the documented k-of-k liveness limit, but the residual-risk text only frames the absent-member-stalls-finalize direction; the unrecoverability (no re-contribution path) is understated. Related but broader than TASK-1 AC#2 (zero-address member), which is one instance of this class.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Add a documented timeout/recovery path returning to Open (allowing re-contribution / re-commit), OR explicitly document that recovery == redeploy + replay contributions
- [ ] #2 Residual-risk text in SealedTally NatSpec + README states the unrecoverability of a stalled instance
<!-- AC:END -->
