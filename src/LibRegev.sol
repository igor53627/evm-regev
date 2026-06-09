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
///
///      Cross-repo note: decrypt32 and innerProduct32 are the 32-bit-lane analogues
///      of evm-lwe-math LibLWE.decryptPow2 / innerProduct12 (which cover 16- and
///      12-bit lanes). Keep the three in step; a shared 32-bit variant upstream in
///      evm-lwe-math is tracked as follow-up.
library LibRegev {
    // 32-bit lanes at even positions (bits 0..31, 64..95, 128..159, 192..223)
    uint256 private constant EVEN_LANES = 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF;
    // 32-bit lanes at odd positions (bits 32..63, 96..127, 160..191, 224..255)
    uint256 private constant ODD_LANES = 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000;

    uint256 private constant Q = 1 << 32;
    uint256 private constant Q_MASK = 0xFFFFFFFF;

    // ──────────────────────────────────────────────────────────────────────
    //  Word-level SWAR helpers (8 x 32-bit lanes, reduction mod 2^32)
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Lane-wise addition mod 2^32 of two packed words.
    /// @dev Even and odd lanes are added separately so that each 32-bit lane has a
    ///      32-bit zeroed gap above it to absorb the carry; the final mask discards
    ///      carries, which is exactly per-lane reduction mod 2^32. ctAdd inlines this
    ///      same SWAR step in its hot loop; this standalone form is the tested unit.
    function addPacked32(uint256 x, uint256 y) internal pure returns (uint256 result) {
        assembly {
            let even := and(add(and(x, EVEN_LANES), and(y, EVEN_LANES)), EVEN_LANES)
            let odd := and(add(and(x, ODD_LANES), and(y, ODD_LANES)), ODD_LANES)
            result := or(even, odd)
        }
    }

    /// @notice Lane-wise multiplication of a packed word by a scalar, mod 2^32.
    /// @param w Scalar multiplier; must be < 2^32 so each lane product fits in its
    ///        64-bit slot. ctScalarMul inlines this; this is the tested unit.
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
    ///      Fused single assembly loop (SWAR add inlined, pointer increments); b is
    ///      reduced mod 2^32 by mask, so an out-of-range b wraps rather than reverting.
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
        assembly {
            let accPtr := add(accA, 32)
            let aPtr := add(a, 32)
            let even := EVEN_LANES
            let odd := ODD_LANES
            for { let i := 0 } lt(i, numWords) { i := add(i, 1) } {
                let x := mload(accPtr)
                let y := mload(aPtr)
                let e := and(add(and(x, even), and(y, even)), even)
                let o := and(add(and(x, odd), and(y, odd)), odd)
                mstore(accPtr, or(e, o))
                accPtr := add(accPtr, 32)
                aPtr := add(aPtr, 32)
            }
            newAccB := and(add(accB, b), Q_MASK)
        }
    }

    /// @notice Homomorphic scalar multiplication: (a, b) -> (w*a, w*b) encrypts w*m.
    /// @dev Mutates a in place. Noise grows by a factor of w; keep w small relative
    ///      to the remaining noise budget. The w bound is checked once, not per word.
    function ctScalarMul(uint256[] memory a, uint256 b, uint256 w, uint256 numWords)
        internal
        pure
        returns (uint256 newB)
    {
        require(a.length >= numWords, "numWords exceeds array length");
        require(w <= Q_MASK, "scalar must be < 2^32");
        assembly {
            let aPtr := add(a, 32)
            let even := EVEN_LANES
            for { let i := 0 } lt(i, numWords) { i := add(i, 1) } {
                let x := mload(aPtr)
                let lo := and(mul(and(x, even), w), even)
                let hi := shl(32, and(mul(and(shr(32, x), even), w), even))
                mstore(aPtr, or(lo, hi))
                aPtr := add(aPtr, 32)
            }
            newB := mulmod(b, w, Q)
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Inner product and decryption
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Computes <a, s> mod 2^32 for 32-bit packed vectors.
    /// @dev Pointer-increment addressing; the 8th lane is already < 2^32 after seven
    ///      shifts, so its mask is omitted.
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
                let wa := mload(aPtr)
                let ws := mload(sPtr)

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

                // 8th lane: wa, ws already < 2^32 after seven shifts
                acc := add(acc, mul(wa, ws))

                aPtr := add(aPtr, 32)
                sPtr := add(sPtr, 32)
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
    /// @param deltaShift log2(Delta), e.g. 16 for q=2^32, p=2^16. Must be in [1, 31]:
    ///        below 1 there is no rounding half, at/above 32 the message would not fit
    ///        the 32-bit modulus. An out-of-range shift reverts rather than silently
    ///        returning 0 (the modulus is fixed at q = 2^32 by this library).
    function decodeMessage(uint256 diff, uint256 deltaShift) internal pure returns (uint256 m) {
        require(deltaShift >= 1 && deltaShift <= 31, "deltaShift out of range");
        assembly {
            let half := shl(sub(deltaShift, 1), 1)
            m := shr(deltaShift, and(add(diff, half), Q_MASK))
        }
    }

    /// @notice Combines additive-share partial decryptions: diff = b - sum(partials) mod q.
    /// @dev For a committee holding additive shares s_1 + ... + s_k = s, each member
    ///      posts p_i = <a, s_i> (+ flooding noise) and the aggregate decrypts without
    ///      ever reconstructing s. Flooding noise must stay within the decode margin.
    ///
    ///      Security caveat for direct callers: summing caller-supplied partials in one
    ///      call lets whoever supplies the array choose the phase (and thus forge the
    ///      message). Cap reveals-per-key to 1 and make partial submission per-member,
    ///      attributed, and commit-revealed on-chain (see examples/SealedTally.sol).
    function combinePartials(uint256 b, uint256[] memory partials) internal pure returns (uint256 diff) {
        uint256 acc = 0;
        uint256 len = partials.length;
        for (uint256 i = 0; i < len; i++) {
            unchecked {
                acc = (acc + partials[i]) & Q_MASK;
            }
        }
        return decrypt32(b, acc);
    }
}
