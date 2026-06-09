// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title RegevParameters
/// @notice Default parameter profile for additively homomorphic Regev encryption on EVM.
/// @dev Profile "TALLY-32": sized for aggregate-reveal applications (encrypted tallies,
///      score accumulators) where many ciphertexts are summed and only the aggregate
///      is ever decrypted.
///
///      LWE parameters:
///        n     = 1536          (secret dimension)
///        q     = 2^32          (ciphertext modulus, power of 2 -> bitmask reduction)
///        sigma ~ 2.83          (centered binomial, k = 16)
///        p     = 2^16          (plaintext modulus; max aggregate value 65535)
///        Delta = q / p = 2^16  (message scaling factor)
///
///      Security (core-SVP, primal uSVP, GSA heuristic; see tools/estimate_lwe.py):
///        ~148-bit classical / ~134-bit quantum.
///        Verify with https://github.com/malb/lattice-estimator before production use.
///
///      Noise budget: a fresh ciphertext carries error with sigma ~ 2.83. After M
///      homomorphic additions the aggregate error has sigma ~ 2.83 * sqrt(M). Decoding
///      is correct while |error| < Delta/2 = 32768, so with a 7.5-sigma margin
///      (failure < 2^-40) the budget allows M ~ 2.3 million additions. The binding
///      constraint is plaintext capacity: the aggregate must stay < p.
///
///      Packing: 8 coefficients per uint256 word, 32-bit lanes, LSB-first
///      (bits 0..31 = element 0). n = 1536 -> 192 packed words per vector.
///
///      Every constant below is either a primitive of the profile or derived from one,
///      so the profile cannot drift internally (e.g. PACKED_WORDS tracks N).
library RegevParameters {
    // ── LWE primitives ────────────────────────────────────────────────────
    uint256 internal constant N = 1536;
    uint256 internal constant Q = 1 << 32;
    uint256 internal constant Q_MASK = Q - 1; // 0xFFFFFFFF
    uint256 internal constant ELEMENTS_PER_WORD = 8; // 256 / 32-bit lanes

    // ── Derived packing ───────────────────────────────────────────────────
    uint256 internal constant PACKED_WORDS = N / ELEMENTS_PER_WORD; // 192

    // ── Plaintext space and message scaling ───────────────────────────────
    uint256 internal constant P = 1 << 16; // max aggregate value 65535
    uint256 internal constant DELTA = Q / P; // 2^16 message scaling factor
    uint256 internal constant DELTA_SHIFT = 16; // log2(DELTA); Q/P = 2^DELTA_SHIFT

    // Noise: centered binomial e = popcount(x[0..15]) - popcount(x[16..31]) gives
    // k = 16, sigma = sqrt(k/2) ~ 2.83, |e| <= 16. See RegevTestUtils.sampleNoise.
}
