// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LibRegev
/// @notice Additively homomorphic Regev (LWE) encryption primitives for the EVM.
/// @dev A ciphertext is a pair (a, b) where a is a packed vector of n coefficients
///      mod q = 2^32 and b is a scalar mod q:
///
///          b = <a, s> + e + Delta * m   (mod q)
///
///      with secret s, small noise e, scaling factor Delta = q/p, and message m < p.
///
///      Homomorphic addition is coefficient-wise: (a1+a2, b1+b2) encrypts m1+m2
///      (mod p), with noise growing as the sum of the individual noise terms.
///
///      Packing: 8 coefficients per uint256, 32-bit lanes, LSB-first
///      (bits 0..31 = element 0). q = 2^32 means per-lane reduction is a bitmask.
///
///      Intended usage pattern (aggregate-reveal): many parties contribute
///      ciphertexts, the contract accumulates them with ctAdd, and only the
///      aggregate is ever decrypted -- either by a designated opener or by a
///      committee posting partial inner products (see combinePartials).
library LibRegev {
    // 32-bit lanes at even positions (bits 0..31, 64..95, 128..159, 192..223)
    uint256 private constant EVEN_LANES = 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF;
    // 32-bit lanes at odd positions (bits 32..63, 96..127, 160..191, 224..255)
    uint256 private constant ODD_LANES = 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000;

    uint256 private constant Q_MASK = 0xFFFFFFFF;

    // ──────────────────────────────────────────────────────────────────────
    //  Word-level SWAR helpers (8 x 32-bit lanes, reduction mod 2^32)
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Lane-wise addition mod 2^32 of two packed words.
    /// @dev Even and odd lanes are added separately so that each 32-bit lane has a
    ///      32-bit zeroed gap above it to absorb the carry; the final mask discards
    ///      carries, which is exactly per-lane reduction mod 2^32.
    function addPacked32(uint256 x, uint256 y) internal pure returns (uint256 result) {
        assembly {
            let even := and(add(and(x, EVEN_LANES), and(y, EVEN_LANES)), EVEN_LANES)
            let odd := and(add(and(x, ODD_LANES), and(y, ODD_LANES)), ODD_LANES)
            result := or(even, odd)
        }
    }

    /// @notice Lane-wise multiplication of a packed word by a scalar, mod 2^32.
    /// @param w Scalar multiplier; must be < 2^32 so each lane product fits in its
    ///        64-bit slot.
    function scalarMulPacked32(uint256 x, uint256 w) internal pure returns (uint256 result) {
        require(w <= Q_MASK, "scalar must be < 2^32");
        assembly {
            let even := and(mul(and(x, EVEN_LANES), w), EVEN_LANES)
            let odd := shl(32, and(mul(and(shr(32, x), EVEN_LANES), w), EVEN_LANES))
            result := or(even, odd)
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Ciphertext operations
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Homomorphic addition: accumulates ciphertext (a, b) into (accA, accB).
    /// @dev Mutates accA in place (memory array) and returns the new b accumulator.
    /// @param accA Packed a-vector accumulator (mutated in place)
    /// @param accB b accumulator
    /// @param a Packed a-vector of the incoming ciphertext
    /// @param b b of the incoming ciphertext
    /// @param numWords Number of packed words (n = numWords * 8)
    /// @return newAccB Updated b accumulator
    function ctAdd(uint256[] memory accA, uint256 accB, uint256[] memory a, uint256 b, uint256 numWords)
        internal
        pure
        returns (uint256 newAccB)
    {
        require(accA.length >= numWords && a.length >= numWords, "numWords exceeds array length");
        for (uint256 i = 0; i < numWords; i++) {
            accA[i] = addPacked32(accA[i], a[i]);
        }
        newAccB = (accB + b) & Q_MASK;
    }

    /// @notice Homomorphic scalar multiplication: (a, b) -> (w*a, w*b) encrypts w*m.
    /// @dev Mutates a in place. Noise grows by a factor of w; keep w small relative
    ///      to the remaining noise budget.
    function ctScalarMul(uint256[] memory a, uint256 b, uint256 w, uint256 numWords)
        internal
        pure
        returns (uint256 newB)
    {
        require(a.length >= numWords, "numWords exceeds array length");
        for (uint256 i = 0; i < numWords; i++) {
            a[i] = scalarMulPacked32(a[i], w);
        }
        newB = mulmod(b, w, 1 << 32);
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Inner product and decryption
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Computes <a, s> mod 2^32 for 32-bit packed vectors.
    /// @param a Packed vector (8 elements per word, LSB-first)
    /// @param s Packed secret vector (same layout)
    /// @param numWords Number of packed words (n = numWords * 8)
    function innerProduct32(uint256[] memory a, uint256[] memory s, uint256 numWords)
        internal
        pure
        returns (uint256 result)
    {
        require(a.length >= numWords && s.length >= numWords, "numWords exceeds array length");
        assembly {
            let aPtr := add(a, 32)
            let sPtr := add(s, 32)
            let acc := 0
            let mask := Q_MASK

            // Each product < 2^64; n = numWords*8 terms keep acc far below 2^256.
            for { let i := 0 } lt(i, numWords) { i := add(i, 1) } {
                let wa := mload(add(aPtr, mul(i, 32)))
                let ws := mload(add(sPtr, mul(i, 32)))

                acc := add(acc, mul(and(wa, mask), and(ws, mask)))
                wa := shr(32, wa)
                ws := shr(32, ws)

                acc := add(acc, mul(and(wa, mask), and(ws, mask)))
                wa := shr(32, wa)
                ws := shr(32, ws)

                acc := add(acc, mul(and(wa, mask), and(ws, mask)))
                wa := shr(32, wa)
                ws := shr(32, ws)

                acc := add(acc, mul(and(wa, mask), and(ws, mask)))
                wa := shr(32, wa)
                ws := shr(32, ws)

                acc := add(acc, mul(and(wa, mask), and(ws, mask)))
                wa := shr(32, wa)
                ws := shr(32, ws)

                acc := add(acc, mul(and(wa, mask), and(ws, mask)))
                wa := shr(32, wa)
                ws := shr(32, ws)

                acc := add(acc, mul(and(wa, mask), and(ws, mask)))
                wa := shr(32, wa)
                ws := shr(32, ws)

                acc := add(acc, mul(and(wa, mask), and(ws, mask)))
            }

            result := and(acc, mask)
        }
    }

    /// @notice Computes the noisy phase (b - innerProd) mod 2^32.
    function decrypt32(uint256 b, uint256 innerProd) internal pure returns (uint256 diff) {
        assembly {
            diff := and(sub(b, innerProd), Q_MASK)
        }
    }

    /// @notice Rounds the noisy phase to the nearest multiple of Delta and returns m.
    /// @param diff Noisy phase: Delta * m + e (mod q), |e| < Delta/2
    /// @param deltaShift log2(Delta), e.g. 16 for q=2^32, p=2^16
    function decodeMessage(uint256 diff, uint256 deltaShift) internal pure returns (uint256 m) {
        assembly {
            let half := shl(sub(deltaShift, 1), 1)
            m := shr(deltaShift, and(add(diff, half), Q_MASK))
        }
    }

    /// @notice Combines additive-share partial decryptions: diff = b - sum(partials) mod q.
    /// @dev For a committee holding additive shares s_1 + ... + s_k = s, each member
    ///      posts p_i = <a, s_i> (+ flooding noise) and the aggregate decrypts without
    ///      ever reconstructing s. Flooding noise must stay within the decode margin.
    function combinePartials(uint256 b, uint256[] memory partials) internal pure returns (uint256 diff) {
        uint256 acc = 0;
        for (uint256 i = 0; i < partials.length; i++) {
            acc = (acc + partials[i]) & Q_MASK;
        }
        diff = (b + (1 << 32) - acc) & Q_MASK;
    }
}
