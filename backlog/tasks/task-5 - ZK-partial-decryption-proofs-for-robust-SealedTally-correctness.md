---
id: TASK-5
title: ZK partial-decryption proofs for robust SealedTally correctness
status: To Do
assignee: []
created_date: '2026-06-11 10:56'
labels:
  - roadmap
  - research
dependencies: []
references:
  - examples/SealedTally.sol
priority: medium
ordinal: 5000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SealedTally commit-reveal prevents a TARGETED forged result and single-party reconstruction of s, but a malicious committee member can still UNDETECTABLY corrupt the tally: commit to a garbage partial that either decodes in-range (wrong-but-accepted result) or out-of-range (DoS, now rescuable via emergencyAbort). k-of-k has no way to attribute a bad partial or prove a posted partial equals the honest <a_agg, s_i>.

Roadmap (stated in SealedTally NatSpec / README): each member attaches a ZK proof that its posted partial = <a_agg, s_i> for its committed share, so finalize() can reject/attribute a dishonest partial -- turning corruption from undetectable into detectable+attributable.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Design a ZK partial-decryption proof binding partial == <a_agg, s_i> to the member's committed share
- [ ] #2 Integrate verification into the reveal/finalize path so a dishonest partial is rejected and attributable
<!-- AC:END -->
