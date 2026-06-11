// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {RegevParameters} from "../src/RegevParameters.sol";
import {RegevTestUtils} from "../src/RegevTestUtils.sol";
import {HiddenScore} from "../examples/HiddenScore.sol";

/// @title KnownAnswerTest
/// @notice Normative known-answer vectors for the off-chain derivations an issuer or
///         committee member must reproduce (a = PRG(ctSeed), s = expandSecret(seed),
///         e = sampleNoise(seed)). Any off-chain reimplementation (Python, Rust, JS)
///         MUST reproduce these exact values, or its ciphertexts/partials will fail to
///         decode against the contract. Treat this file as the cross-language spec for
///         the keccak/abi.encode PRG, not just a Solidity test.
///
/// All vectors use seed = keccak256("REGEV-KAT-v1").
///   expandSecret(seed, 1)[0]  -- one packed word of the secret (8x 32-bit lanes)
///   deriveA(seed, 1)[0]       -- one packed word of an a-vector
///   sampleNoise(seed, 0)      -- centered-binomial noise as a value mod 2^32
///   encrypt(expandSecret(seed,192), 42, keccak256("REGEV-KAT-ct")).b -- full ciphertext scalar
contract KnownAnswerTest is Test {
    bytes32 constant SEED = keccak256("REGEV-KAT-v1");

    function test_kat_expandSecret() public pure {
        uint256[] memory s = RegevTestUtils.expandSecret(SEED, 1);
        assertEq(bytes32(s[0]), 0x263a9e14dcc39d95395b6730e12add9447f6d7cbe75afdf06a1fdf5bbab8f234);
    }

    function test_kat_deriveA() public pure {
        uint256[] memory a = RegevTestUtils.deriveA(SEED, 1);
        assertEq(bytes32(a[0]), 0xce28afddec8b78e6cff6994af5ca045f6a49d80c2596a8ac547404e617e3e50d);
    }

    function test_kat_sampleNoise() public pure {
        // 4294967294 = 2^32 - 2, i.e. e = -2 in two's complement mod 2^32.
        assertEq(RegevTestUtils.sampleNoise(SEED, 0), 4294967294);
    }

    function test_kat_encrypt() public pure {
        uint256[] memory s = RegevTestUtils.expandSecret(SEED, RegevParameters.PACKED_WORDS);
        (, uint256 b) = RegevTestUtils.encrypt(s, 42, keccak256("REGEV-KAT-ct"));
        assertEq(b, 3974789295);
        // And it round-trips back to 42 under the same key.
        (uint256[] memory a,) = RegevTestUtils.encrypt(s, 42, keccak256("REGEV-KAT-ct"));
        assertEq(RegevTestUtils.decryptFull(a, b, s), 42);
    }

    // ── Composite off-chain derivations (beyond the PRG primitives above) ──
    // These pin the abi.encode framing of the higher-level derivations an off-chain
    // issuer/committee must reproduce: getting the heterogeneous-type encoding wrong
    // (address padding, field order, the chainid term) decodes to a wrong-but-accepted
    // score, so the framing is normative, not incidental.

    bytes32 constant KAT_PLAYER_KEY_DOMAIN = keccak256("HIDDENSCORE_PLAYER_KEY_v1");

    /// Guard: the KAT's local domain copy must equal the deployed contract's constant, so a
    /// domain bump (e.g. _v2) breaks this loudly instead of letting the spec silently drift.
    function test_kat_playerKeyDomain_matchesContract() public {
        HiddenScore game = new HiddenScore(address(1), address(2), bytes32(0));
        assertEq(game.PLAYER_KEY_DOMAIN(), KAT_PLAYER_KEY_DOMAIN);
    }

    /// HiddenScore per-player key seed:
    ///   keccak256(abi.encode(DOMAIN, masterSeed, player, chainid, game))
    /// Pinned with literal chainid = 1 and fixed player/game addresses so the vector is
    /// environment-independent (the live contract substitutes block.chainid/address(this)).
    function test_kat_playerKeySeed() public pure {
        bytes32 seed =
            keccak256(abi.encode(KAT_PLAYER_KEY_DOMAIN, SEED, address(0xCAFE), uint256(1), address(0xABCD)));
        assertEq(seed, 0xc201dea2c34280a6238382da5067f417da817e6036df11c094cacc9474cbfc4c);
    }

    /// HiddenScore seed-digest fold: d_0 = 0; d_{i+1} = keccak256(abi.encode(d_i, ctSeed_i)).
    function test_kat_seedDigestFold() public pure {
        bytes32 d = bytes32(0);
        d = keccak256(abi.encode(d, keccak256("ct0")));
        d = keccak256(abi.encode(d, keccak256("ct1")));
        assertEq(d, 0xd23583f4b719481422d36a3a03ae8573a0659c6396378c048d7e7bca26d2b378);
    }

    /// SealedTally additive sharing splitSecretK(s, shareSeed, 3): pseudorandom share 0
    /// and the lane-wise remainder share (k-1) are both pinned (the remainder exercises
    /// the per-lane mod-2^32 subtraction, the most error-prone part to reimplement).
    function test_kat_splitSecretK() public pure {
        uint256[] memory s = RegevTestUtils.expandSecret(SEED, 2);
        uint256[][] memory shares = RegevTestUtils.splitSecretK(s, keccak256("REGEV-KAT-share"), 3);
        assertEq(bytes32(shares[0][0]), 0x00e2e1eefc0315866f31724f07cf957b88cab189e88e9a7721c232891edc9cc2);
        assertEq(bytes32(shares[2][0]), 0x3f73365019ba26b4e0c7d0ba3a858737329e89dcd11518c7bb31a8b0127ff403);
    }

    /// SealedTally commitment preimage an off-chain member must reproduce exactly:
    ///   keccak256(abi.encode(instanceId, snapshotDigest, idx, partial, salt))
    /// A field-order/encoding mismatch here fails the same fail-open way the score path
    /// would, so the framing is pinned with fixed literal inputs.
    function test_kat_commitmentPreimage() public pure {
        bytes32 c = keccak256(
            abi.encode(
                bytes32(uint256(0xABCD)), // instanceId
                bytes32(uint256(0x1234)), // snapshotDigest
                uint8(2), // idx (1-based)
                uint256(0xDEADBEEF), // partial
                bytes32(uint256(0x5A17)) // salt
            )
        );
        assertEq(c, 0x373c7d6231756ba34707e0ea092150f957b51d05944f3da9433688d720864e3f);
    }
}
