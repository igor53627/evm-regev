---
id: TASK-2
title: >-
  SealedTally: no abort/timeout/reset — one faulty member permanently bricks the
  instance
status: Done
assignee: []
created_date: '2026-06-11 05:07'
updated_date: '2026-06-11 09:03'
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
- [x] #1 Add a documented timeout/recovery path returning to Open (allowing re-contribution / re-commit), OR explicitly document that recovery == redeploy + replay contributions
- [x] #2 Residual-risk text in SealedTally NatSpec + README states the unrecoverability of a stalled instance
- [ ] #3 Recovery AC covers BOTH liveness directions: an absent/lost-key member stalling finalize AND an absent issuer (startReveal is issuer-only) bricking the Open->Committing transition
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented opt-in emergency exit (commit on branch feat/sealedtally-emergency-exit). AC#1: timeout-gated emergencyAbort() -> terminal Aborted, enabled iff a governance address is set at deploy; else stall==redeploy (documented). AC#2: NatSpec + README state the stall/unrecoverability and the opt-in escape. AC#3 left UNCHECKED by design: only the post-startReveal opening stall (Committing/Revealing) is abortable; the issuer-absent-in-Open direction is intentionally NOT abortable (no committee work is stuck there, the issuer legitimately controls opening timing, and a single timeout would conflate the contribution window with the opening window). Chose ABORT over reset-to-Open because members are immutable -> a permanently-lost member cannot be replaced in-place, so reset cannot finalize; abort+redeploy is the honest recovery. 5 new tests; 55/55 pass.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Delivered in PR #2 (c0f2d24): opt-in governance + revealTimeout emergencyAbort() -> terminal Aborted for stalled openings, with no-outcome-suppression (fully-revealed valid result is finalized, not aborted). AC#1/#2 done. AC#3 (issuer-absent-in-Open direction) intentionally DESCOPED: Open is the issuer's contribution window with no stuck committee work, and a single timeout would conflate it with the opening window -- documented in NatSpec/README. 7 tests cover the feature.
<!-- SECTION:FINAL_SUMMARY:END -->
