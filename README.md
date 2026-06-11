# evm-regev

[![CI](https://github.com/igor53627/evm-regev/actions/workflows/test.yml/badge.svg)](https://github.com/igor53627/evm-regev/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Solidity ^0.8.20](https://img.shields.io/badge/Solidity-%5E0.8.20-363636?logo=solidity)](https://soliditylang.org)
[![Built with Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFDB1C)](https://getfoundry.sh)

Additively homomorphic Regev (LWE) encryption for the EVM.

## What it provides

The cheapest-by-gas additively homomorphic encryption available on vanilla EVM:
ciphertext addition is bitmasked 32-bit lane arithmetic (no `MULMOD` over big
moduli, no pairings, no modexp), and the scheme is plausibly post-quantum.

The 32-bit inner product and phase subtraction (`innerProduct32`, `decrypt32`)
are delegated to the audited [evm-lwe-math](https://github.com/igor53627/evm-lwe-math)
library (added as a submodule); the Regev-specific homomorphic ops live here.

| Module | Purpose |
|--------|---------|
| `LibRegev` | Homomorphic add / scalar-mul, packed inner product, decrypt, decode, partial-decryption combine |
| `RegevParameters` | Default parameter profile (TALLY-32) |
| `RegevTestUtils` | Key generation, noise sampling, encrypt/decrypt, additive k-of-k share split (test/dev only) |
| `examples/HiddenScore.sol` | Encrypted score accumulator — single trusted opener, per-player keys |
| `examples/SealedTally.sol` | Encrypted aggregate tally — real on-chain k-of-k committee (commit-reveal) |

## The pattern: aggregate-reveal

Many parties contribute encrypted values; the contract accumulates them
homomorphically; **only the aggregate is ever decrypted**. Compared to
commit-reveal of plaintexts: one transaction per participant, no plaintext
reveal phase, no "reveal-or-be-slashed" liveness problem, and individual values
are never published.

Target applications:

- **Hidden running tallies** in DAO voting (no bandwagon effects, no last-minute
  sniping; only the final result is revealed)
- **Dark-pool / batch-auction order flow** (only the net imbalance is revealed
  at clearing)
- **Demand aggregation** in token sales (oversubscription ratio without exposing
  individual bids)
- **On-chain games** with hidden scores/resources (issuer-encrypted increments)

## Scheme

Symmetric Regev encryption over `Z_q`:

```text
ct = (a, b),   b = <a, s> + e + Delta * m   (mod q)
```

Addition of ciphertexts adds the underlying messages (mod `p`). Decryption
rounds the phase `b - <a, s>` to the nearest multiple of `Delta = q/p`.

Because decryption is **linear in `s`**, threshold opening is cheap: give
committee members additive shares `s_1 + ... + s_k = s`; each posts the scalar
`<a_agg, s_i>`; the contract combines them with `LibRegev.combinePartials` and
no party ever reconstructs `s`. **But summing caller-supplied partials safely
requires per-member attribution and commit-reveal on-chain** — see
`examples/SealedTally.sol`; do not just accept a partials array in one call (the
supplier could choose the phase and forge the result).

## The two examples

The aggregate-reveal pattern hides values, but **revealing a value publishes an
exact linear equation in the key** (`<a_agg, s>` is exactly recoverable once the
score and accumulator are public). Recovering an `n = 1536`-dimensional key needs
≥ 1536 such equations, so the design must guarantee each key is opened few times.
The two examples take the two honest routes:

### `HiddenScore` — single trusted opener, per-player keys

Each player has an **independent** key `s_player = expandSecret(keccak256(DOMAIN,
masterSeed, player, block.chainid, address(this)))`. Revealing a player publishes
**one exact equation** in *that player's* key only (the public ciphertext scalars
`b_i` are noisy LWE samples, not exact equations); equations never accumulate against
a common unknown, and the player is **retired on reveal** (one open per key). Even
under an adversarial credit/reveal race (reverted-reveal calldata leaks exact
partials) the count per key is bounded by `MAX_CREDITS = 255`, leaving a margin of
≥ 1536 − 256 ≈ 1280 to recovery — the fix is structural, needs no noise flooding, and
needs no parameter change. The opener is a single trusted party
(it knows `s_player`, so trusting it to open honestly adds no new assumption).
**No committee, no threshold** — for that, use `SealedTally`.

### `SealedTally` — real on-chain k-of-k committee

The per-instance key is additively shared across `k` members. To open, **each
member submits its own partial on-chain** (`msg.sender`-attributed), via a
**commit-reveal where all commitments lock before any reveal**, bound to a frozen
snapshot of the accumulator. This closes the forgery surface a single
partials-array reveal would open: the issuer cannot supply a member's partial,
no single party controls the sum, and the last revealer cannot see others'
values to bias the result. A malicious member can still corrupt a tally (caught
as a failed/abandoned reveal), but cannot forge a *targeted* result; `k`-of-`k`
has no Byzantine fault tolerance (one absent member stalls finalize, like a
multisig).

**Optional emergency exit.** Constructor takes `(issuer, members, governance,
revealTimeout)`. Pass a non-zero `governance` (a multisig / DAO / timelock) to enable
`emergencyAbort()`: once `revealTimeout` elapses on a stalled opening, governance can move
the tally to a terminal **Aborted** state — turning a silent permanent stall into an
explicit, observable dead-end (then redeploy). To prevent outcome suppression, a
*fully-revealed* opening that decodes validly is **finalized** (not aborted), so governance
can never wait for a determined result and abort an unfavorable one — it can only finalize a
determined result or kill a genuinely stalled/corrupted opening, never fabricate or suppress
one, so it adds no forgery or bias power. Because members are immutable it is
abort-and-redeploy, not in-place recovery. Pass `governance = address(0)` to keep the pure
k-of-k model (stall ⇒ redeploy only). The Open phase is intentionally not abortable — the
issuer alone decides when to open.

## Default parameters (TALLY-32)

| Parameter | Value | Note |
|-----------|-------|------|
| Dimension n | 1536 | 192 packed words |
| Modulus q | 2^32 | power of 2, bitmask reduction |
| Plaintext p | 2^16 | aggregate must stay < 65,536 |
| Noise | centered binomial k=16, sigma ~ 2.83 | |
| Security (Core-SVP, primal uSVP) | ~148-bit classical / ~134-bit quantum | `tools/estimate_lwe.py` |
| Noise budget | ~2.3M additions (failure < 2^-40) | plaintext capacity binds first |

Packing: 8 coefficients per `uint256`, 32-bit lanes, LSB-first. Ciphertext =
192 words for `a` + 1 word for `b` (6,176 bytes). With seed-derived `a`-vectors
(issuer model), only `(seed, b)` — 2 words — ever touches the chain.

Estimates use the simplified GSA heuristic; verify with the
[lattice estimator](https://github.com/malb/lattice-estimator) before
production use.

## Gas benchmarks (Foundry, optimizer on)

| Operation | Parameters | Gas |
|-----------|-----------|-----|
| `ctAdd` (memory) | 192 words, n=1536 | ~28K |
| `innerProduct32` | 192 words, n=1536 | ~70K |
| `HiddenScore.credit()` | first / subsequent | ~74K / ~58K |
| `HiddenScore.reveal()` | single partial | ~32K † |
| `SealedTally.finalize()` | k=3 | ~41K † |

`ctAdd` / `innerProduct32` / `credit()` are pinned by gas tests (`test_gas_*`,
`test_credit_gas`). † `reveal()` / `finalize()` are point-in-time full-transaction
estimates (incl. 21k base + cold SLOADs), not test-pinned; the `test_reveal_gas` /
`test_finalize_gas` probes log warm-execution gas as a drift signal.

`credit()`/`contribute()` pay one cold `usedSeed` SSTORE (~20K, F6 seed
uniqueness) plus a `seedDigest` running-hash SSTORE (F5 snapshot binding); these
guards are the cost of the integrity properties and are why a credit is dearer
than a bare accumulator add. Numbers are with the solc optimizer enabled
(`foundry.toml`); disabling it inflates them materially.

## Trust model and honest caveats

Read this before building on the library:

1. **The issuer is fully trusted.** It knows every key (HiddenScore) / contributes
   all ciphertexts (SealedTally), so within the off-chain per-increment bound it can
   encrypt `Enc(anything)`, decline to reveal, or post an honest-looking partial for a
   fabricated value. The `DecodeOutOfRange` range checks prove only
   partial-vs-accumulator/in-range consistency; they do **not** prove credited
   increments were honest. Inherent to the issuer model; removing it needs ZK validity
   proofs (Roadmap).
2. **Per-increment magnitude is not enforced on-chain.** `MAX_INCREMENT` is documented,
   not cryptographically enforced (encryption is off-chain). The `MAX_CREDITS` count cap
   prevents only *accidental* mod-`p` wrap, not a malicious issuer over-crediting.
3. **Committee correctness (SealedTally).** Commit-reveal stops a *targeted* forged
   result and any single party reconstructing `s`, but a malicious member can still
   corrupt the decode (caught as a failed/abandoned reveal, or a wrong-but-in-range
   value). `k`-of-`k` has no Byzantine fault tolerance; robust correctness needs ZK
   partial-decryption proofs (Roadmap).
4. **Per-key open count is load-bearing.** Safety rests on each key being opened
   ≈ once (HiddenScore retires a player on reveal; SealedTally finalizes once). The
   HiddenScore key binds `block.chainid` and `address(this)`, so the same `masterSeed`
   and player yield *different* keys across chains/instances; only reusing one
   `masterSeed` at a CREATE2-identical address on the *same* chain would compose
   equations (still ≪ 1536, but the contract cannot prevent off-chain key reuse).
5. **No flooding noise.** TALLY-32 (`Delta/2 = 2^15`) has no headroom for flooding; the
   design needs none because safety is structural (per-key open-count bound), not
   noise-based.
6. **Native ETH amounts cannot be hidden** — transaction values are public. The scheme
   is for abstract quantities: votes, scores, order sizes, allocations.
7. **Metadata leaks.** Seeds, `b` values, counts, and timing are public; only the
   aggregate value is hidden until reveal. Seeds live in event logs — reconstruction
   depends on log availability.
8. **Secrets must never touch the chain.** Encryption and partial decryption happen
   off-chain; the contract only adds, combines, and decodes. `test/KnownAnswer.t.sol`
   pins the derivation (`a = PRG(ctSeed)`, `s = expandSecret`, `e = sampleNoise`) as a
   normative reference for off-chain reimplementations.
9. **No recovery after finalize.** `revealed`/`Finalized` is irreversible; the F4/F5
   pre-commit checks make a wrong freeze far less likely but do not undo one.

## Core API

```solidity
import {LibRegev} from "evm-regev/src/LibRegev.sol";

// Homomorphic accumulation (memory arrays, packed 32-bit lanes)
accB = LibRegev.ctAdd(accA, accB, a, b, numWords);

// Weighted contribution: (a, b) -> Enc(w * m)
newB = LibRegev.ctScalarMul(a, b, w, numWords);

// Single-opener decryption
uint256 ip = LibRegev.innerProduct32(a, s, numWords);
uint256 score = LibRegev.decodeMessage(LibRegev.decrypt32(b, ip), DELTA_SHIFT);

// Threshold opening from additive-share partials (attribute + commit-reveal these
// on-chain per member; see SealedTally)
uint256 diff = LibRegev.combinePartials(b, partials);
uint256 tally = LibRegev.decodeMessage(diff, DELTA_SHIFT);
```

## Build and test

```bash
git submodule update --init --recursive
forge build
forge test -vv
```

Parameter sizing:

```bash
python3 tools/estimate_lwe.py
```

## Roadmap

- **Public-key mode** (Regev PKE: `a' = r^T A`, `b' = r^T pk + Delta*m`) so
  permissionless contributors can encrypt without knowing `s` — required for
  voting/auction use cases
- **Shamir t-of-n threshold** (requires a prime-modulus profile; additive n-of-n
  shares are supported today)
- **ZK validity proofs** for ciphertexts and partial decryptions

## Related projects

- [evm-lwe-math](https://github.com/igor53627/evm-lwe-math) — gas-optimized LWE inner-product primitives
- [evm-linear-accumulator](https://github.com/igor53627/evm-linear-accumulator) — seed-derived linear hash accumulator over Z_q
- [evm-mhf](https://github.com/igor53627/evm-mhf) — EVM-native memory-hard function
- [evm-lattice-pow](https://github.com/igor53627/evm-lattice-pow) — lattice-based proof of work
- [lwe-jump-table](https://github.com/igor53627/lwe-jump-table) — LWE-based control flow flattening (origin of this extraction)

## License

MIT
