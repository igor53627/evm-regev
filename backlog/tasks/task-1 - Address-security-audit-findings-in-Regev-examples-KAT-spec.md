---
id: TASK-1
title: Address security audit findings in Regev examples & KAT spec
status: In Progress
assignee: []
created_date: '2026-06-11 04:43'
updated_date: '2026-06-11 05:50'
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
- Info (doc accuracy): HiddenScore "<=2 equations per key" understates the true bound (reverted-reveal calldata is public and partials are exact -> up to MAX_CREDITS=255 independent equations; margin to 1536 still holds, ~1281). combinePartials natspec dangles "+flooding noise" that TALLY-32 (delta/2=2^15) cannot support. issuer/opener split in HiddenScore is operational, not a trust reduction (both hold full key material).

roborev jobs: 6995/6996/6997 (security, codex) = no issues (diff-scoped); 6998 (design, claude-code) = Pass with corroborating notes on KAT drift, liveness/griefing, and the loose "<=2" phrasing. Design Finding 1 (member can freeze early) is STALE — already fixed: current startReveal() is issuer-only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 SealedTally constructor rejects issuer in _members and requires k>=2 (or explicitly documents k=1 == single trusted opener); regression test reproduces and then blocks the issuer-as-member forgery PoC (true=100 vs forged=65000)
- [x] #2 Both example constructors reject zero-address roles/members (HiddenScore issuer/opener; SealedTally members)
- [x] #3 KnownAnswer.t.sol pins normative KAT vectors for the per-player key seed composition, the seedDigest keccak fold, and splitSecretK, closing the fail-open cross-implementation gap
- [ ] #4 High-entropy (>=128-bit random) salt requirement for SealedTally commitments is documented and the example demonstrates a random (non-deterministic) salt
- [x] #5 HiddenScore per-player key derivation includes block.chainid (spec + KAT vector)
- [x] #6 Docs corrected: '<=2 equations' -> '<=MAX_CREDITS, margin >=1281'; combinePartials '+flooding noise' removed/marked unsupported at TALLY-32; HiddenScore issuer/opener split clarified as operational not trust-reducing
- [x] #7 Missing gas probes added for HiddenScore.reveal() and SealedTally.finalize() (README table rows currently unpinned)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
All ACs except #4 implemented; 48/48 tests green. AC#4: the >=128-bit CSPRNG salt requirement is DOCUMENTED (commitPartial natspec + test salt() helper), but the example intentionally keeps deterministic salts for reproducible KAT vectors, so AC#4 (literal 'example demonstrates a random salt') is left unchecked -- a random-salt demo is a deferred follow-up. roborev (post-commit) also caught a missing SealedTally _issuer zero-check, now fixed + tested.
<!-- SECTION:NOTES:END -->
