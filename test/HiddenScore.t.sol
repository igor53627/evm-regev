// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {LibRegev} from "../src/LibRegev.sol";
import {RegevParameters} from "../src/RegevParameters.sol";
import {RegevTestUtils} from "../src/RegevTestUtils.sol";
import {HiddenScore} from "../examples/HiddenScore.sol";

contract HiddenScoreTest is Test {
    uint256 constant WORDS = RegevParameters.PACKED_WORDS;
    uint256 constant Q_MASK = 0xFFFFFFFF;

    address issuer = address(0xBEEF);
    address player = address(0xCAFE);

    HiddenScore game;
    uint256[] secret;

    function setUp() public {
        game = new HiddenScore(issuer);
        secret = RegevTestUtils.expandSecret(keccak256("issuer-secret"), WORDS);
    }

    /// Issuer-side encryption with a seed-derived a-vector (done off-chain in reality).
    function encryptIncrement(uint256 m, bytes32 ctSeed) internal view returns (uint256 b) {
        uint256[] memory a = RegevTestUtils.deriveA(ctSeed, WORDS);
        uint256 ip = LibRegev.innerProduct32(a, secret, WORDS);
        uint256 e = RegevTestUtils.sampleNoise(ctSeed, 0);
        b = (ip + e + (m << RegevParameters.DELTA_SHIFT)) & Q_MASK;
    }

    function test_creditAndReveal_singleOpener() public {
        uint256[3] memory increments = [uint256(100), 250, 31];
        bytes32[3] memory seeds = [keccak256("c0"), keccak256("c1"), keccak256("c2")];

        vm.startPrank(issuer);
        for (uint256 i = 0; i < 3; i++) {
            game.credit(player, seeds[i], encryptIncrement(increments[i], seeds[i]));
        }

        // Opener recomputes a_agg off-chain from Credited events and posts <a_agg, s>.
        uint256[] memory aAgg = new uint256[](WORDS);
        for (uint256 i = 0; i < 3; i++) {
            uint256[] memory a = RegevTestUtils.deriveA(seeds[i], WORDS);
            LibRegev.ctAdd(aAgg, 0, a, 0, WORDS);
        }
        uint256[] memory partials = new uint256[](1);
        partials[0] = LibRegev.innerProduct32(aAgg, secret, WORDS);

        game.reveal(player, partials);
        vm.stopPrank();

        (,, bool revealed, uint256 score) = game.players(player);
        assertTrue(revealed);
        assertEq(score, 100 + 250 + 31, "revealed score wrong");
    }

    function test_creditAndReveal_committeeShares() public {
        (uint256[] memory s1, uint256[] memory s2) = RegevTestUtils.splitSecret(secret, keccak256("committee"));

        bytes32 seed0 = keccak256("k0");
        bytes32 seed1 = keccak256("k1");

        vm.startPrank(issuer);
        game.credit(player, seed0, encryptIncrement(7, seed0));
        game.credit(player, seed1, encryptIncrement(35, seed1));

        uint256[] memory aAgg = new uint256[](WORDS);
        LibRegev.ctAdd(aAgg, 0, RegevTestUtils.deriveA(seed0, WORDS), 0, WORDS);
        LibRegev.ctAdd(aAgg, 0, RegevTestUtils.deriveA(seed1, WORDS), 0, WORDS);

        // Each committee member posts a partial over its own share; s is never rebuilt.
        uint256[] memory partials = new uint256[](2);
        partials[0] = LibRegev.innerProduct32(aAgg, s1, WORDS);
        partials[1] = LibRegev.innerProduct32(aAgg, s2, WORDS);

        game.reveal(player, partials);
        vm.stopPrank();

        (,, bool revealed, uint256 score) = game.players(player);
        assertTrue(revealed);
        assertEq(score, 42, "committee reveal wrong");
    }

    function test_credit_gas() public {
        bytes32 seed0 = keccak256("g0");
        uint256 b = encryptIncrement(1, seed0);
        vm.prank(issuer);
        uint256 g0 = gasleft();
        game.credit(player, seed0, b);
        emit log_named_uint("credit() gas", g0 - gasleft());
    }

    function test_onlyIssuer() public {
        vm.expectRevert(HiddenScore.NotIssuer.selector);
        game.credit(player, bytes32(0), 1);
    }

    function test_noDoubleReveal() public {
        vm.startPrank(issuer);
        bytes32 seed0 = keccak256("d0");
        game.credit(player, seed0, encryptIncrement(5, seed0));

        uint256[] memory aAgg = RegevTestUtils.deriveA(seed0, WORDS);
        uint256[] memory partials = new uint256[](1);
        partials[0] = LibRegev.innerProduct32(aAgg, secret, WORDS);
        game.reveal(player, partials);

        vm.expectRevert(HiddenScore.AlreadyRevealed.selector);
        game.reveal(player, partials);
        vm.stopPrank();
    }
}
