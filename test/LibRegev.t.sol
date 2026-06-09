// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {LibRegev} from "../src/LibRegev.sol";
import {RegevParameters} from "../src/RegevParameters.sol";
import {RegevTestUtils} from "../src/RegevTestUtils.sol";

contract LibRegevTest is Test {
    uint256 constant Q_MASK = 0xFFFFFFFF;
    uint256 constant WORDS = RegevParameters.PACKED_WORDS;
    uint256 constant SHIFT = RegevParameters.DELTA_SHIFT;
    uint256 constant P = RegevParameters.P;

    // ──────────────────────────────────────────────────────────────────────
    //  SWAR word helpers vs lane-by-lane reference
    // ──────────────────────────────────────────────────────────────────────

    function getLane(uint256 word, uint256 lane) internal pure returns (uint256) {
        return (word >> (lane * 32)) & Q_MASK;
    }

    function testFuzz_addPacked32(uint256 x, uint256 y) public pure {
        uint256 r = LibRegev.addPacked32(x, y);
        for (uint256 lane = 0; lane < 8; lane++) {
            uint256 expected = (getLane(x, lane) + getLane(y, lane)) & Q_MASK;
            assertEq(getLane(r, lane), expected, "lane mismatch in addPacked32");
        }
    }

    function testFuzz_scalarMulPacked32(uint256 x, uint32 w) public pure {
        uint256 r = LibRegev.scalarMulPacked32(x, w);
        for (uint256 lane = 0; lane < 8; lane++) {
            uint256 expected = (getLane(x, lane) * w) & Q_MASK;
            assertEq(getLane(r, lane), expected, "lane mismatch in scalarMulPacked32");
        }
    }

    function test_addPacked32_carryIsolation() public pure {
        // All lanes at q-1: every lane must wrap to q-2 without leaking carries.
        uint256 allMax = type(uint256).max;
        uint256 r = LibRegev.addPacked32(allMax, allMax);
        for (uint256 lane = 0; lane < 8; lane++) {
            assertEq(getLane(r, lane), Q_MASK - 1, "carry leaked between lanes");
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Encrypt / decrypt roundtrip
    // ──────────────────────────────────────────────────────────────────────

    function test_encryptDecryptRoundtrip() public pure {
        uint256[] memory s = RegevTestUtils.expandSecret(keccak256("key"), WORDS);
        uint256[4] memory messages = [uint256(0), 1, 12345, P - 1];
        for (uint256 i = 0; i < messages.length; i++) {
            (uint256[] memory a, uint256 b) = RegevTestUtils.encrypt(s, messages[i], keccak256(abi.encode("ct", i)));
            assertEq(RegevTestUtils.decryptFull(a, b, s), messages[i], "roundtrip failed");
        }
    }

    function testFuzz_encryptDecryptRoundtrip(uint16 m, bytes32 rseed) public pure {
        uint256[] memory s = RegevTestUtils.expandSecret(keccak256("fuzz-key"), WORDS);
        (uint256[] memory a, uint256 b) = RegevTestUtils.encrypt(s, m, rseed);
        assertEq(RegevTestUtils.decryptFull(a, b, s), m, "fuzz roundtrip failed");
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Homomorphic addition
    // ──────────────────────────────────────────────────────────────────────

    function test_homomorphicSum() public pure {
        uint256[] memory s = RegevTestUtils.expandSecret(keccak256("sum-key"), WORDS);
        uint256[] memory accA = new uint256[](WORDS);
        uint256 accB = 0;
        uint256 expectedSum = 0;

        for (uint256 i = 0; i < 100; i++) {
            uint256 m = uint256(keccak256(abi.encode("msg", i))) % 100;
            expectedSum += m;
            (uint256[] memory a, uint256 b) = RegevTestUtils.encrypt(s, m, keccak256(abi.encode("sum-ct", i)));
            accB = LibRegev.ctAdd(accA, accB, a, b, WORDS);
        }

        assertLt(expectedSum, P, "test invariant: aggregate must fit plaintext space");
        assertEq(RegevTestUtils.decryptFull(accA, accB, s), expectedSum, "homomorphic sum wrong");
    }

    function test_noiseBudget_manyAdditions() public pure {
        // 500 additions: aggregate noise sigma ~ 2.83 * sqrt(500) ~ 63, margin is 32768.
        uint256[] memory s = RegevTestUtils.expandSecret(keccak256("budget-key"), WORDS);
        uint256[] memory accA = new uint256[](WORDS);
        uint256 accB = 0;

        for (uint256 i = 0; i < 500; i++) {
            (uint256[] memory a, uint256 b) = RegevTestUtils.encrypt(s, 1, keccak256(abi.encode("budget-ct", i)));
            accB = LibRegev.ctAdd(accA, accB, a, b, WORDS);
        }

        assertEq(RegevTestUtils.decryptFull(accA, accB, s), 500, "decode failed within budget");
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Homomorphic scalar multiplication
    // ──────────────────────────────────────────────────────────────────────

    function test_ctScalarMul() public pure {
        uint256[] memory s = RegevTestUtils.expandSecret(keccak256("mul-key"), WORDS);
        (uint256[] memory a, uint256 b) = RegevTestUtils.encrypt(s, 321, keccak256("mul-ct"));
        uint256 newB = LibRegev.ctScalarMul(a, b, 7, WORDS);
        assertEq(RegevTestUtils.decryptFull(a, newB, s), 7 * 321, "scalar mul wrong");
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Threshold (additive-share) decryption
    // ──────────────────────────────────────────────────────────────────────

    function test_partialDecryption() public pure {
        uint256[] memory s = RegevTestUtils.expandSecret(keccak256("thr-key"), WORDS);
        (uint256[] memory s1, uint256[] memory s2) = RegevTestUtils.splitSecret(s, keccak256("share-seed"));

        (uint256[] memory a, uint256 b) = RegevTestUtils.encrypt(s, 4242, keccak256("thr-ct"));

        uint256[] memory partials = new uint256[](2);
        partials[0] = LibRegev.innerProduct32(a, s1, WORDS);
        partials[1] = LibRegev.innerProduct32(a, s2, WORDS);

        uint256 diff = LibRegev.combinePartials(b, partials);
        assertEq(LibRegev.decodeMessage(diff, SHIFT), 4242, "partial decryption wrong");
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Gas measurements
    // ──────────────────────────────────────────────────────────────────────

    function test_gas_innerProduct32() public {
        uint256[] memory s = RegevTestUtils.expandSecret(keccak256("gas-key"), WORDS);
        uint256[] memory a = RegevTestUtils.deriveA(keccak256("gas-a"), WORDS);
        uint256 g0 = gasleft();
        uint256 ip = LibRegev.innerProduct32(a, s, WORDS);
        uint256 used = g0 - gasleft();
        emit log_named_uint("innerProduct32 (192 words, n=1536) gas", used);
        assertLt(ip, 1 << 32);
    }

    function test_gas_ctAdd() public {
        uint256[] memory accA = new uint256[](WORDS);
        uint256[] memory a = RegevTestUtils.deriveA(keccak256("gas-add"), WORDS);
        uint256 g0 = gasleft();
        uint256 accB = LibRegev.ctAdd(accA, 0, a, 123, WORDS);
        uint256 used = g0 - gasleft();
        emit log_named_uint("ctAdd (192 words, n=1536) gas", used);
        assertEq(accB, 123);
    }
}
