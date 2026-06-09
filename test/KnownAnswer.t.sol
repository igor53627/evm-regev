// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {RegevParameters} from "../src/RegevParameters.sol";
import {RegevTestUtils} from "../src/RegevTestUtils.sol";

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
}
