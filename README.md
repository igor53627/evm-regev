# evm-regev

Additively homomorphic Regev (LWE) encryption for the EVM.

## What it provides

The cheapest-by-gas additively homomorphic encryption available on vanilla EVM:
ciphertext addition is bitmasked 32-bit lane arithmetic (no `MULMOD` over big
moduli, no pairings, no modexp), and the scheme is plausibly post-quantum.

| Module | Purpose |
|--------|---------|
| `LibRegev` | Homomorphic add / scalar-mul, packed inner product, decrypt, decode, partial-decryption combine |
| `RegevParameters` | Default parameter profile (TALLY-32) |
| `RegevTestUtils` | Key generation, noise sampling, encrypt/decrypt (test/dev only) |
| `examples/HiddenScore.sol` | Encrypted score accumulator (issuer model, seed-derived a-vectors) |

## The pattern: aggregate-reveal

Many parties contribute encrypted values; the contract accumulates them
homomorphically; **only the aggregate is ever decrypted**. Compared to
commit-reveal: one transaction per participant, no reveal phase, no
"reveal-or-be-slashed" liveness problem, and individual values are never
published.

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

Because decryption is **linear in `s`**, threshold opening is nearly free: give
committee members additive shares `s_1 + ... + s_k = s`; each posts the scalar
`<a_agg, s_i>`; the contract combines them with `LibRegev.combinePartials` and
no party ever reconstructs `s`.

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

## Gas benchmarks (Foundry)

| Operation | Parameters | Gas |
|-----------|-----------|-----|
| `ctAdd` (memory) | 192 words, n=1536 | ~64K |
| `innerProduct32` | 192 words, n=1536 | ~108K |
| `HiddenScore.credit()` | seed-derived a, 2 storage words | ~55K |
| `addPacked32` (per word) | 8 lanes | ~36 |

## Trust model and honest caveats

Read this before building on the library:

1. **Ciphertext validity is not verifiable on-chain.** A malicious contributor
   can encrypt `Enc(10^6)` instead of `Enc(1)` and skew the aggregate. Options:
   a trusted/signing issuer (games, oracles — free), ZK range proofs for lattice
   ciphertexts (heavy, future work), or economically bounded contributions.
   Deploy permissionless-contributor designs only with one of these.
2. **Openers are trusted for correctness.** A wrong partial decryption decodes
   to a wrong aggregate. ZK proofs of correct partial decryption are future
   work; until then use a committee you would also trust as a multisig.
3. **One key per instance.** Each reveal publishes one linear equation in each
   share; a long-lived key degrades over many reveals. Use fresh keys, or add
   flooding noise to partials and budget for it.
4. **Native ETH amounts cannot be hidden** — transaction values are public.
   The scheme is for abstract quantities: votes, scores, order sizes,
   allocations.
5. **Secrets must never touch the chain.** Encryption and partial decryption
   happen off-chain; the contract only adds, combines, and decodes.

## Core API

```solidity
import {LibRegev} from "evm-regev/src/LibRegev.sol";

// Homomorphic accumulation (memory arrays, packed 32-bit lanes)
accB = LibRegev.ctAdd(accA, accB, a, b, numWords);

// Weighted contribution: (a, b) -> Enc(w * m)
newB = LibRegev.ctScalarMul(a, b, w, numWords);

// Decryption (opener side)
uint256 ip = LibRegev.innerProduct32(a, s, numWords);
uint256 m = LibRegev.decodeMessage(LibRegev.decrypt32(b, ip), DELTA_SHIFT);

// Threshold opening from additive-share partials
uint256 diff = LibRegev.combinePartials(b, partials);
uint256 m = LibRegev.decodeMessage(diff, DELTA_SHIFT);
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
- **Flooding-noise helpers** for multi-reveal key reuse

## Related projects

- [evm-lwe-math](https://github.com/igor53627/evm-lwe-math) — gas-optimized LWE inner-product primitives
- [evm-linear-accumulator](https://github.com/igor53627/evm-linear-accumulator) — seed-derived linear hash accumulator over Z_q
- [evm-mhf](https://github.com/igor53627/evm-mhf) — EVM-native memory-hard function
- [evm-lattice-pow](https://github.com/igor53627/evm-lattice-pow) — lattice-based proof of work
- [lwe-jump-table](https://github.com/igor53627/lwe-jump-table) — LWE-based control flow flattening (origin of this extraction)

## License

MIT
