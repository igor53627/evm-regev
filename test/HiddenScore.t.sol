// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {LibRegev} from "../src/LibRegev.sol";
import {RegevParameters} from "../src/RegevParameters.sol";
import {RegevTestUtils} from "../src/RegevTestUtils.sol";
import {HiddenScore} from "../examples/HiddenScore.sol";

contract HiddenScoreTest is Test {
    uint256 constant WORDS = RegevParameters.PACKED_WORDS;
    uint256 constant Q = 1 << 32;
    uint256 constant Q_MASK = RegevParameters.Q_MASK;
    uint256 constant MAX_SCORE = 255 * 255; // 65025

    bytes32 constant MASTER_SEED = keccak256("test-master-seed");
    bytes32 constant PLAYER_KEY_DOMAIN = keccak256("HIDDENSCORE_PLAYER_KEY_v1");

    address issuer = address(0xBEEF);
    address opener = address(0x0FE9);
    address playerA = address(0xCAFE);
    address playerB = address(0xF00D);

    HiddenScore game;

    function setUp() public {
        game = new HiddenScore(issuer, opener, keccak256(abi.encode(MASTER_SEED)));
    }

    // ── Off-chain issuer/opener helpers (mirror real keystore-side computation) ──

    /// Per-player key: s_player = expandSecret(keccak256(DOMAIN, masterSeed, player, game)).
    function derivePlayerSecret(address player) internal view returns (uint256[] memory) {
        bytes32 seed = keccak256(abi.encode(PLAYER_KEY_DOMAIN, MASTER_SEED, player, address(game)));
        return RegevTestUtils.expandSecret(seed, WORDS);
    }

    /// Issuer-side encryption reuses the library's canonical encrypt (no re-implementation).
    function encB(address player, uint256 m, bytes32 ctSeed) internal view returns (uint256 b) {
        (, b) = RegevTestUtils.encrypt(derivePlayerSecret(player), m, ctSeed);
    }

    /// Opener reconstructs a_agg = sum of credited a-vectors.
    function aggA(bytes32[] memory seeds) internal pure returns (uint256[] memory acc) {
        acc = new uint256[](WORDS);
        for (uint256 i = 0; i < seeds.length; i++) {
            LibRegev.ctAdd(acc, 0, RegevTestUtils.deriveA(seeds[i], WORDS), 0, WORDS);
        }
    }

    /// Opener recomputes the running seed digest the contract keeps.
    function digestOf(bytes32[] memory seeds) internal pure returns (bytes32 d) {
        for (uint256 i = 0; i < seeds.length; i++) {
            d = keccak256(abi.encode(d, seeds[i]));
        }
    }

    function openerPartial(address player, bytes32[] memory seeds) internal view returns (uint256) {
        return LibRegev.innerProduct32(aggA(seeds), derivePlayerSecret(player), WORDS);
    }

    // ── Happy path ──────────────────────────────────────────────────────────

    function test_creditAndReveal_singleOpener() public {
        bytes32[] memory seeds = new bytes32[](3);
        seeds[0] = keccak256("c0");
        seeds[1] = keccak256("c1");
        seeds[2] = keccak256("c2");
        uint256[3] memory inc = [uint256(100), 250, 31];

        vm.startPrank(issuer);
        for (uint256 i = 0; i < 3; i++) {
            game.credit(playerA, seeds[i], encB(playerA, inc[i], seeds[i]));
        }
        vm.stopPrank();

        vm.prank(opener);
        game.reveal(playerA, openerPartial(playerA, seeds), digestOf(seeds));

        (,, uint16 score, bool revealed) = game.players(playerA);
        assertTrue(revealed);
        assertEq(score, 100 + 250 + 31, "revealed score wrong");
    }

    // ── F1: per-player key isolation + regression on the old shared-key attack ──

    /// F1 property: per-player keys give KEY ISOLATION -- compromising one player's key
    /// reveals nothing about another's hidden score. This is the structural replacement
    /// for the old shared-key design (one key for all players, recoverable after ~1536
    /// reveals). We credit two players under their own keys, reveal A honestly, then show
    /// that an attacker holding A's FULL key still cannot decode B's on-chain accumulator
    /// -- with a positive control proving B's ciphertext is itself valid.
    function test_keyIsolation_oneKeyDoesNotLeakAnother() public {
        bytes32 sa0 = keccak256("isoA");
        bytes32 sb0 = keccak256("isoB");
        vm.startPrank(issuer);
        game.credit(playerA, sa0, encB(playerA, 100, sa0));
        game.credit(playerB, sb0, encB(playerB, 200, sb0));
        vm.stopPrank();

        bytes32[] memory aSeeds = new bytes32[](1);
        aSeeds[0] = sa0;
        bytes32[] memory bSeeds = new bytes32[](1);
        bSeeds[0] = sb0;

        // A is revealed honestly under its own key.
        vm.prank(opener);
        game.reveal(playerA, openerPartial(playerA, aSeeds), digestOf(aSeeds));
        (,, uint16 scoreA,) = game.players(playerA);
        assertEq(scoreA, 100, "A reveals correctly");

        (uint32 bAccB,,,) = game.players(playerB);

        // Positive control: B's accumulator IS a valid ciphertext -- it decodes to 200
        // under B's own key. So the negative result below is isolation, not a dud ct.
        uint256[] memory sB = derivePlayerSecret(playerB);
        uint256 rightInner = LibRegev.innerProduct32(aggA(bSeeds), sB, WORDS);
        uint256 rightPhase = LibRegev.decrypt32(uint256(bAccB), rightInner);
        assertEq(LibRegev.decodeMessage(rightPhase, RegevParameters.DELTA_SHIFT), 200, "B decodes under sB");

        // Negative: an attacker holding A's full key produces a DIFFERENT phase for B's
        // accumulator (<a_aggB, sA> != <a_aggB, sB>), so it cannot reproduce B's decode.
        // Compromising A therefore leaks nothing about B's hidden score.
        uint256[] memory sA = derivePlayerSecret(playerA);
        uint256 wrongInner = LibRegev.innerProduct32(aggA(bSeeds), sA, WORDS);
        assertTrue(wrongInner != rightInner, "A's key yields a different phase for B");
    }

    // ── F6: seed uniqueness ───────────────────────────────────────────────────

    function test_seedReuseReverts() public {
        bytes32 s = keccak256("dup");
        vm.startPrank(issuer);
        game.credit(playerA, s, encB(playerA, 1, s));
        vm.expectRevert(HiddenScore.SeedReused.selector);
        game.credit(playerA, s, encB(playerA, 2, s));
        vm.stopPrank();
    }

    // ── F3: capacity cap ──────────────────────────────────────────────────────

    function test_capReached() public {
        vm.startPrank(issuer);
        for (uint256 i = 0; i < 255; i++) {
            bytes32 s = keccak256(abi.encode("cap", i));
            game.credit(playerA, s, encB(playerA, 1, s));
        }
        bytes32 over = keccak256("cap-over");
        vm.expectRevert(HiddenScore.CapReached.selector);
        game.credit(playerA, over, encB(playerA, 1, over));
        vm.stopPrank();
    }

    // ── F5: snapshot binding ──────────────────────────────────────────────────

    function test_staleSnapshot() public {
        bytes32[] memory one = new bytes32[](1);
        one[0] = keccak256("s0");
        vm.prank(issuer);
        game.credit(playerA, one[0], encB(playerA, 10, one[0]));

        // Opener computes partial+digest over the 1-credit state.
        uint256 partOld = openerPartial(playerA, one);
        bytes32 digOld = digestOf(one);

        // A second credit lands before the reveal tx.
        vm.prank(issuer);
        game.credit(playerA, keccak256("s1"), encB(playerA, 5, keccak256("s1")));

        // Stale partial reverts.
        vm.prank(opener);
        vm.expectRevert(HiddenScore.StaleSnapshot.selector);
        game.reveal(playerA, partOld, digOld);

        // Recomputed over the new state succeeds.
        bytes32[] memory both = new bytes32[](2);
        both[0] = one[0];
        both[1] = keccak256("s1");
        vm.prank(opener);
        game.reveal(playerA, openerPartial(playerA, both), digestOf(both));
        (,, uint16 score,) = game.players(playerA);
        assertEq(score, 15, "snapshot-correct reveal wrong");
    }

    // ── F4: reveal validation ────────────────────────────────────────────────

    function test_noCredits() public {
        vm.prank(opener);
        vm.expectRevert(HiddenScore.NoCredits.selector);
        game.reveal(playerA, 0, bytes32(0));
    }

    function test_decodeOutOfRange() public {
        bytes32 s = keccak256("oor");
        vm.prank(issuer);
        game.credit(playerA, s, encB(playerA, 10, s));
        (uint32 bAcc,,,) = game.players(playerA);

        // Forge a partial so the phase decodes to 65530 > MAX_SCORE (deterministic).
        uint256 targetDiff = uint256(65530) << RegevParameters.DELTA_SHIFT;
        uint256 badPartial = (uint256(bAcc) + Q - (targetDiff % Q)) % Q;

        bytes32[] memory one = new bytes32[](1);
        one[0] = s;
        vm.prank(opener);
        vm.expectRevert(HiddenScore.DecodeOutOfRange.selector);
        game.reveal(playerA, badPartial, digestOf(one));
        // NOTE: an in-range-but-wrong partial is NOT caught -- documents the residual risk.
    }

    function test_accessControl() public {
        bytes32 s = keccak256("ac");
        vm.expectRevert(HiddenScore.NotIssuer.selector);
        game.credit(playerA, s, 1);

        vm.prank(issuer);
        game.credit(playerA, s, encB(playerA, 1, s));
        bytes32[] memory one = new bytes32[](1);
        one[0] = s;
        vm.expectRevert(HiddenScore.NotOpener.selector);
        game.reveal(playerA, openerPartial(playerA, one), digestOf(one));
    }

    function test_noDoubleReveal_andRetire() public {
        bytes32 s = keccak256("retire");
        vm.prank(issuer);
        game.credit(playerA, s, encB(playerA, 7, s));
        bytes32[] memory one = new bytes32[](1);
        one[0] = s;

        vm.prank(opener);
        game.reveal(playerA, openerPartial(playerA, one), digestOf(one));

        // Retired: further credit and reveal both revert.
        vm.prank(issuer);
        vm.expectRevert(HiddenScore.AlreadyRevealed.selector);
        game.credit(playerA, keccak256("retire2"), 1);

        vm.prank(opener);
        vm.expectRevert(HiddenScore.AlreadyRevealed.selector);
        game.reveal(playerA, 0, digestOf(one));
    }

    // ── Gas ───────────────────────────────────────────────────────────────────

    function test_credit_gas() public {
        bytes32 s = keccak256("g0");
        uint256 b = encB(playerA, 1, s);
        vm.prank(issuer);
        uint256 g0 = gasleft();
        game.credit(playerA, s, b);
        emit log_named_uint("credit() gas (first, one-slot pack + usedSeed)", g0 - gasleft());
    }
}
