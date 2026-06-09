// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LibRegev} from "./LibRegev.sol";
import {RegevParameters} from "./RegevParameters.sol";

/// @title RegevTestUtils
/// @notice Key generation, noise sampling, and encryption for tests and tooling.
/// @dev TEST/DEV ONLY. Real deployments must generate secrets and encrypt off-chain;
///      a secret that ever touches calldata or contract state is public.
library RegevTestUtils {
    bytes32 private constant SECRET_DOMAIN = keccak256("REGEV_SECRET_v1");
    bytes32 private constant A_DOMAIN = keccak256("REGEV_A_v1");
    bytes32 private constant NOISE_DOMAIN = keccak256("REGEV_NOISE_v1");

    uint256 private constant Q_MASK = 0xFFFFFFFF;

    // ──────────────────────────────────────────────────────────────────────
    //  Key and vector generation
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Expands a seed into a packed uniform secret vector (8 x 32-bit per word).
    function expandSecret(bytes32 seed, uint256 numWords) internal pure returns (uint256[] memory s) {
        s = new uint256[](numWords);
        for (uint256 j = 0; j < numWords; j++) {
            // One keccak word = exactly 8 uniform 32-bit lanes (no modulo bias).
            s[j] = uint256(keccak256(abi.encode(SECRET_DOMAIN, seed, j)));
        }
    }

    /// @notice Derives a packed a-vector from a per-ciphertext seed.
    function deriveA(bytes32 seed, uint256 numWords) internal pure returns (uint256[] memory a) {
        a = new uint256[](numWords);
        for (uint256 j = 0; j < numWords; j++) {
            a[j] = uint256(keccak256(abi.encode(A_DOMAIN, seed, j)));
        }
    }

    /// @notice Samples centered binomial noise (k = 16, sigma ~ 2.83) as a value mod 2^32.
    function sampleNoise(bytes32 seed, uint256 idx) internal pure returns (uint256 e) {
        uint256 h = uint256(keccak256(abi.encode(NOISE_DOMAIN, seed, idx)));
        uint256 pos = popcount(h & 0xFFFF);
        uint256 neg = popcount((h >> 16) & 0xFFFF);
        // Two's complement representation mod 2^32
        e = ((1 << 32) + pos - neg) & Q_MASK;
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Encrypt / decrypt
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Symmetric Regev encryption: b = <a, s> + e + Delta * m (mod q).
    /// @param s Packed secret vector
    /// @param m Message, must be < P
    /// @param rseed Per-ciphertext randomness seed (determines a and e)
    /// @return a Packed a-vector
    /// @return b Ciphertext scalar
    function encrypt(uint256[] memory s, uint256 m, bytes32 rseed)
        internal
        pure
        returns (uint256[] memory a, uint256 b)
    {
        require(m < RegevParameters.P, "message exceeds plaintext space");
        a = deriveA(rseed, RegevParameters.PACKED_WORDS);
        uint256 ip = LibRegev.innerProduct32(a, s, RegevParameters.PACKED_WORDS);
        uint256 e = sampleNoise(rseed, 0);
        b = (ip + e + (m << RegevParameters.DELTA_SHIFT)) & Q_MASK;
    }

    /// @notice Full decryption: recovers m from (a, b) given the secret s.
    function decryptFull(uint256[] memory a, uint256 b, uint256[] memory s) internal pure returns (uint256 m) {
        uint256 ip = LibRegev.innerProduct32(a, s, RegevParameters.PACKED_WORDS);
        uint256 diff = LibRegev.decrypt32(b, ip);
        m = LibRegev.decodeMessage(diff, RegevParameters.DELTA_SHIFT);
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Additive secret sharing (for threshold-decryption tests)
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Splits s into two additive shares: s = s1 + s2 (lane-wise mod 2^32).
    function splitSecret(uint256[] memory s, bytes32 shareSeed)
        internal
        pure
        returns (uint256[] memory s1, uint256[] memory s2)
    {
        uint256 numWords = s.length;
        s1 = expandSecret(shareSeed, numWords);
        s2 = new uint256[](numWords);
        for (uint256 j = 0; j < numWords; j++) {
            uint256 w2 = 0;
            for (uint256 lane = 0; lane < 8; lane++) {
                uint256 vs = (s[j] >> (lane * 32)) & Q_MASK;
                uint256 v1 = (s1[j] >> (lane * 32)) & Q_MASK;
                uint256 v2 = ((1 << 32) + vs - v1) & Q_MASK;
                w2 |= v2 << (lane * 32);
            }
            s2[j] = w2;
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Bit utilities
    // ──────────────────────────────────────────────────────────────────────

    function popcount(uint256 x) internal pure returns (uint256 count) {
        while (x != 0) {
            x &= x - 1;
            count++;
        }
    }
}
