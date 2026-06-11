---
id: TASK-1
title: Address security audit findings in Regev examples & KAT spec
status: Done
assignee: []
created_date: '2026-06-11 04:43'
updated_date: '2026-06-11 09:27'
labels:
  - security
  - audit
dependencies: []
references:
  - examples/SealedTally.sol
  - examples/HiddenScore.sol
  - test/KnownAnswer.t.sol
priority: high
ordinal: 1000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Audit of additively-homomorphic Regev (LWE) library + examples. Method: ultra-granular context build, parallel adversarial hunt, PoC verification, plus independent roborev (3x codex security + 1x claude-code design).

VERDICT: crypto/math core is sound (SWAR add/scalar-mul lane containment, innerProduct32 mod-2^32 reduction, decryptPow2, decodeMessage rounding, sampleNoise CBD, split-share invariant, combinePartials) and estimate_lwe.py does not overstate the ~148/~134-bit claim. Findings are at the contract-config, cross-implementation-spec, and documentation layers.

HEADLINE (PoC-proven, Medium): SealedTally constructor does not exclude the issuer from `_members`. Since the issuer knows the full secret s, an issuer that is also a committee member can unilaterally forge an arbitrary in-range finalize result (commit-reveal gives no protection: the forging partial is precomputable from s + own share). A passing Foundry PoC drove finalize() to 65000 while the true aggregate was 100, with honest k-1 members and no collusion. None of the roborev reviews flagged this (all assume the standard issuer-disjoint config, which the contract does not enforce).

OTHER FINDINGS:
- Medium: KnownAnswer.t.sol is advertised as the cross-language spec but does NOT pin the per-player key seed composition keccak256(abi.encode(DOMAIN,masterSeed,player,this)), the seedDigest fold, or splitSecretK. The per-player-key path fails OPEN: a cross-impl framing disagreement yields a uniform-random score that passes DecodeOutOfRange (>65025) ~99.2% of the time -> silent wrong-but-accepted decode. (Independently echoed by roborev design review: "cross-language KAT drift".)
- Low: SealedTally commit hiding rests entirely on salt entropy; the committed partial is only 32 bits and the example/test uses a public deterministic salt keccak256(abi.encode("salt",i)). With a weak/predictable salt a last committer can brute-force (~2^32 keccak) earlier partials and aim, defeating "last submitter cannot bias".
- Low: SealedTally allows k=1 (require n>=1); a single member then holds all of s and can forge, contradicting "no single trusted opener".
- Low: HiddenScore per-player key derivation omits block.chainid; same-address (CREATE2) cross-chain deploy + reused masterSeed -> shared key, equations compose across chains.
- Low/Info: constructors do not reject zero addresses; a zero-address SealedTally member permanently bricks the instance (independently echoed by roborev: no abort/timeout/reset; single faulty member bricks instance).
- Info (doc accuracy): HiddenScore "<=2 equations per key" understates the true bound (reverted-reveal calldata is public and partials are exact -> up to MAX_CREDITS=255 independent equations; margin to 1536 still holds, ~1280 = 1536-256, i.e. 255 credit-equations + the 1 reveal-equation). combinePartials natspec dangles "+flooding noise" that TALLY-32 (delta/2=2^15) cannot support. issuer/opener split in HiddenScore is operational, not a trust reduction (both hold full key material).

roborev jobs: 6995/6996/6997 (security, codex) = no issues (diff-scoped); 6998 (design, claude-code) = Pass with corroborating notes on KAT drift, liveness/griefing, and the loose "<=2" phrasing. Design Finding 1 (member can freeze early) is STALE — already fixed: current startReveal() is issuer-only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 SealedTally constructor rejects issuer in _members and requires k>=2 (or explicitly documents k=1 == single trusted opener), making the issuer-as-member forgery PoC (true=100 vs forged=65000) unconstructable; asserted by test_constructor_rejectsIssuerAsMember / test_constructor_rejectsSingleMemberCommittee
- [x] #2 Both example constructors reject zero-address roles/members (HiddenScore issuer/opener; SealedTally members)
- [x] #3 KnownAnswer.t.sol pins normative KAT vectors for the per-player key seed composition, the seedDigest keccak fold, and splitSecretK, closing the fail-open cross-implementation gap
- [x] #4 High-entropy (>=128-bit random) salt requirement for SealedTally commitments is documented and the example demonstrates a random (non-deterministic) salt
- [x] #5 HiddenScore per-player key derivation includes block.chainid (spec + KAT vector)
- [x] #6 Docs corrected: '<=2 equations' -> '<=MAX_CREDITS, margin ~1280'; combinePartials '+flooding noise' removed/marked unsupported at TALLY-32; HiddenScore issuer/opener split clarified as operational not trust-reducing
- [x] #7 Missing gas probes added for HiddenScore.reveal() and SealedTally.finalize() (README table rows currently unpinned)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
All 7 ACs delivered. AC#1-3/#5-7 in PR #1 (audit remediation); AC#4 in PR #3 via test_happyPath_randomSalt + test_predictableSalt_leaksPartialToBruteForce. See the final summary for the per-AC detail.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
All 7 ACs delivered across PR #1 (audit remediation) and this change (AC#4). AC#4: added test_happyPath_randomSalt (demonstrates the recommended fresh-CSPRNG-salt pattern end-to-end via vm.randomUint) and test_predictableSalt_leaksPartialToBruteForce (demonstrates the failure mode -- a predictable salt makes the ~32-bit committed partial a brute-force oracle; a random salt closes it). The >=128-bit CSPRNG requirement is documented in commitPartial natspec + the test salt() helper.
<!-- SECTION:FINAL_SUMMARY:END -->
