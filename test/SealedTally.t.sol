// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {LibRegev} from "../src/LibRegev.sol";
import {RegevParameters} from "../src/RegevParameters.sol";
import {RegevTestUtils} from "../src/RegevTestUtils.sol";
import {SealedTally} from "../examples/SealedTally.sol";

contract SealedTallyTest is Test {
    uint256 constant WORDS = RegevParameters.PACKED_WORDS;
    uint256 constant Q_MASK = RegevParameters.Q_MASK;
    uint8 constant K = 3;

    bytes32 constant MASTER = keccak256("tally-master");
    bytes32 constant SHARE_SEED = keccak256("tally-shares");

    address issuer = address(0xBEEF);
    address observer = address(0xDEAD);
    address governance = address(0x6011); // emergency-exit authority for the governed tests
    uint64 constant ABORT_TIMEOUT = 7 days;
    address[] members;

    SealedTally tally;
    uint256[] s; // instance secret
    uint256[][] shares; // K additive shares

    function setUp() public {
        members.push(address(0xA11));
        members.push(address(0xB22));
        members.push(address(0xC33));
        tally = new SealedTally(issuer, members, address(0), 0); // emergency exit off
        s = RegevTestUtils.expandSecret(MASTER, WORDS);
        shares = RegevTestUtils.splitSecretK(s, SHARE_SEED, K);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function encB(uint256 m, bytes32 ctSeed) internal view returns (uint256 b) {
        (, b) = RegevTestUtils.encrypt(s, m, ctSeed);
    }

    function aggA(bytes32[] memory seeds) internal pure returns (uint256[] memory acc) {
        acc = new uint256[](WORDS);
        for (uint256 i = 0; i < seeds.length; i++) {
            LibRegev.ctAdd(acc, 0, RegevTestUtils.deriveA(seeds[i], WORDS), 0, WORDS);
        }
    }

    /// Computes each member's partial over the frozen snapshot's a_agg.
    function memberPartials(bytes32[] memory seeds) internal view returns (uint256[] memory parts) {
        uint256[] memory aAgg = aggA(seeds);
        parts = new uint256[](K);
        for (uint256 i = 0; i < K; i++) {
            parts[i] = LibRegev.innerProduct32(aAgg, shares[i], WORDS);
        }
    }

    /// TEST-ONLY deterministic salts (for reproducible vectors). REAL deployments MUST
    /// use a >= 128-bit CSPRNG salt kept secret until reveal: the committed partial is
    /// only ~32 bits, so a predictable salt is brute-forceable (see commitPartial natspec).
    function salt(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encode("salt", i));
    }

    /// Builds all k commitments with a SINGLE pair of external reads (no prank active),
    /// so the per-member prank loops contain no prank-consuming external calls.
    function buildCommits(uint256[] memory parts) internal view returns (bytes32[] memory commits) {
        bytes32 iid = tally.instanceId();
        bytes32 snapDig = tally.snapshotDigest();
        commits = new bytes32[](K);
        for (uint256 i = 0; i < K; i++) {
            commits[i] = keccak256(abi.encode(iid, snapDig, uint8(i + 1), parts[i], salt(i)));
        }
    }

    /// Drives a full successful tally over the given seeds/messages and returns the result.
    function runTally(bytes32[] memory seeds, uint256[] memory ms) internal returns (uint16) {
        vm.startPrank(issuer);
        for (uint256 i = 0; i < seeds.length; i++) {
            tally.contribute(seeds[i], encB(ms[i], seeds[i]));
        }
        tally.startReveal();
        vm.stopPrank();

        uint256[] memory parts = memberPartials(seeds);
        bytes32[] memory commits = buildCommits(parts);
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            tally.commitPartial(commits[i]);
        }
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            tally.revealPartial(parts[i], salt(i));
        }
        tally.finalize();
        (,,, uint16 result) = tally.tally();
        return result;
    }

    function twoContribs() internal pure returns (bytes32[] memory seeds, uint256[] memory ms) {
        seeds = new bytes32[](2);
        seeds[0] = keccak256("t0");
        seeds[1] = keccak256("t1");
        ms = new uint256[](2);
        ms[0] = 100;
        ms[1] = 50;
    }

    // ── Happy path ──────────────────────────────────────────────────────────

    function test_happyPath_kOfk() public {
        (bytes32[] memory seeds, uint256[] memory ms) = twoContribs();
        assertEq(runTally(seeds, ms), 150, "tally wrong");
        (,, uint8 phase,) = tally.tally();
        assertEq(phase, uint8(SealedTally.Phase.Finalized));
    }

    // ── F2: issuer cannot forge ───────────────────────────────────────────────

    function test_issuerCannotForge() public {
        (bytes32[] memory seeds, uint256[] memory ms) = twoContribs();
        vm.startPrank(issuer);
        for (uint256 i = 0; i < seeds.length; i++) {
            tally.contribute(seeds[i], encB(ms[i], seeds[i]));
        }
        tally.startReveal();
        // (1) Attribution: issuer cannot impersonate a member to inject a partial.
        vm.expectRevert(SealedTally.NotMember.selector);
        tally.commitPartial(bytes32(uint256(1)));
        // (2) No shortcut: finalize needs phase Revealing, reached only once all k members
        //     have committed -> the issuer cannot unilaterally produce ANY result.
        vm.expectRevert(SealedTally.WrongPhase.selector);
        tally.finalize();
        vm.stopPrank();

        // (3) Even after the honest committee commits, the issuer still cannot reveal on a
        //     member's behalf, and the honest finalize yields the TRUE sum (150), not an
        //     issuer-chosen value -> the issuer has no lever over the committee result.
        uint256[] memory parts = memberPartials(seeds);
        bytes32[] memory commits = buildCommits(parts);
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            tally.commitPartial(commits[i]);
        }
        vm.prank(issuer);
        vm.expectRevert(SealedTally.NotMember.selector);
        tally.revealPartial(parts[0], salt(0));

        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            tally.revealPartial(parts[i], salt(i));
        }
        tally.finalize();
        (,,, uint16 result) = tally.tally();
        assertEq(result, 150, "issuer cannot deviate the committee result");
    }

    // ── F2: last submitter cannot bias ────────────────────────────────────────

    function test_lastSubmitterCannotBias() public {
        (bytes32[] memory seeds, uint256[] memory ms) = twoContribs();
        vm.startPrank(issuer);
        for (uint256 i = 0; i < seeds.length; i++) {
            tally.contribute(seeds[i], encB(ms[i], seeds[i]));
        }
        tally.startReveal();
        vm.stopPrank();

        uint256[] memory parts = memberPartials(seeds);
        bytes32[] memory commits = buildCommits(parts);
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            tally.commitPartial(commits[i]);
        }
        // The last member, having seen others reveal, tries a DIFFERENT partial to bias
        // the result. Its commitment is locked -> BadReveal. It cannot aim.
        vm.prank(members[0]);
        tally.revealPartial(parts[0], salt(0));
        vm.prank(members[1]);
        tally.revealPartial(parts[1], salt(1));
        vm.prank(members[2]);
        vm.expectRevert(SealedTally.BadReveal.selector);
        tally.revealPartial(parts[2] ^ 0x1234, salt(2));
    }

    // ── F4: missing partial blocks finalize ───────────────────────────────────

    function test_missingPartialBlocksFinalize() public {
        (bytes32[] memory seeds, uint256[] memory ms) = twoContribs();
        vm.startPrank(issuer);
        for (uint256 i = 0; i < seeds.length; i++) {
            tally.contribute(seeds[i], encB(ms[i], seeds[i]));
        }
        tally.startReveal();
        vm.stopPrank();

        uint256[] memory parts = memberPartials(seeds);
        bytes32[] memory commits = buildCommits(parts);
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            tally.commitPartial(commits[i]);
        }
        // Only K-1 reveal.
        vm.prank(members[0]);
        tally.revealPartial(parts[0], salt(0));
        vm.prank(members[1]);
        tally.revealPartial(parts[1], salt(1));

        vm.expectRevert(SealedTally.IncompletePartials.selector);
        tally.finalize();
    }

    function test_doubleRevealReverts() public {
        (bytes32[] memory seeds, uint256[] memory ms) = twoContribs();
        vm.startPrank(issuer);
        for (uint256 i = 0; i < seeds.length; i++) {
            tally.contribute(seeds[i], encB(ms[i], seeds[i]));
        }
        tally.startReveal();
        vm.stopPrank();

        uint256[] memory parts = memberPartials(seeds);
        bytes32[] memory commits = buildCommits(parts);
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            tally.commitPartial(commits[i]);
        }
        vm.prank(members[0]);
        tally.revealPartial(parts[0], salt(0));
        vm.prank(members[0]);
        vm.expectRevert(SealedTally.AlreadyRevealed.selector);
        tally.revealPartial(parts[0], salt(0));
    }

    // ── F6 / F3 / F5 guards ────────────────────────────────────────────────────

    function test_seedReuseReverts() public {
        bytes32 sd = keccak256("dup");
        vm.startPrank(issuer);
        tally.contribute(sd, encB(1, sd));
        vm.expectRevert(SealedTally.SeedReused.selector);
        tally.contribute(sd, encB(2, sd));
        vm.stopPrank();
    }

    function test_capReached() public {
        vm.startPrank(issuer);
        for (uint256 i = 0; i < 255; i++) {
            bytes32 sd = keccak256(abi.encode("cap", i));
            tally.contribute(sd, encB(1, sd));
        }
        bytes32 over = keccak256("cap-over");
        vm.expectRevert(SealedTally.CapReached.selector);
        tally.contribute(over, encB(1, over));
        vm.stopPrank();
    }

    function test_contributeAfterSnapshotReverts() public {
        bytes32 sd = keccak256("c0");
        vm.startPrank(issuer);
        tally.contribute(sd, encB(1, sd));
        tally.startReveal();
        vm.expectRevert(SealedTally.WrongPhase.selector);
        tally.contribute(keccak256("c1"), encB(1, keccak256("c1")));
        vm.stopPrank();
    }

    function test_startRevealGated() public {
        bytes32 sd = keccak256("c0");
        vm.prank(issuer);
        tally.contribute(sd, encB(1, sd));
        // Neither an outsider nor a committee member can freeze the snapshot early:
        // only the issuer (sole contributor) signals "done contributing".
        vm.prank(observer);
        vm.expectRevert(SealedTally.NotIssuer.selector);
        tally.startReveal();
        vm.prank(members[0]);
        vm.expectRevert(SealedTally.NotIssuer.selector);
        tally.startReveal();
    }

    // ── Forgery-surface hardening (issuer must be disjoint from the committee) ──

    /// An issuer that is also a committee member knows the full secret s AND holds a
    /// share, so it could forge an arbitrary finalized result (commit-reveal gives no
    /// protection: the forging partial is precomputable from s). The constructor must
    /// reject this configuration outright.
    function test_constructor_rejectsIssuerAsMember() public {
        address[] memory bad = new address[](3);
        bad[0] = members[0];
        bad[1] = issuer; // issuer also holds a committee share
        bad[2] = members[2];
        vm.expectRevert(bytes("issuer cannot be a member"));
        new SealedTally(issuer, bad, address(0), 0);
    }

    /// k == 1 is a single member holding all of s (a single trusted opener that can
    /// forge), which contradicts the k-of-k "no single trusted opener" model.
    function test_constructor_rejectsSingleMemberCommittee() public {
        address[] memory one = new address[](1);
        one[0] = members[0];
        vm.expectRevert(bytes("k out of range"));
        new SealedTally(issuer, one, address(0), 0);
    }

    /// A zero issuer permanently bricks contribute()/startReveal() (no caller is
    /// address(0)), leaving the instance stuck in Open.
    function test_constructor_rejectsZeroIssuer() public {
        vm.expectRevert(bytes("zero issuer address"));
        new SealedTally(address(0), members, address(0), 0);
    }

    // ── Gas ───────────────────────────────────────────────────────────────────

    function test_finalize_gas() public {
        (bytes32[] memory seeds, uint256[] memory ms) = twoContribs();
        vm.startPrank(issuer);
        for (uint256 i = 0; i < seeds.length; i++) {
            tally.contribute(seeds[i], encB(ms[i], seeds[i]));
        }
        tally.startReveal();
        vm.stopPrank();
        uint256[] memory parts = memberPartials(seeds);
        bytes32[] memory commits = buildCommits(parts);
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            tally.commitPartial(commits[i]);
        }
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            tally.revealPartial(parts[i], salt(i));
        }
        uint256 g0 = gasleft();
        tally.finalize();
        emit log_named_uint("finalize() warm-exec gas (k=3; excl. 21k base + cold SLOADs)", g0 - gasleft());
    }

    // ── Emergency exit (opt-in governance + timeout) ────────────────────────────

    /// Deploys a governed tally and drives it into a stalled Committing phase (only k-1
    /// members commit), returning it ready to be aborted once the timeout elapses.
    function _stalledGovernedTally() internal returns (SealedTally g) {
        g = new SealedTally(issuer, members, governance, ABORT_TIMEOUT);
        bytes32 sd = keccak256("g0");
        vm.startPrank(issuer);
        g.contribute(sd, encB(1, sd));
        g.startReveal();
        vm.stopPrank();
        for (uint256 i = 0; i + 1 < K; i++) {
            vm.prank(members[i]); // one member never commits -> stuck Committing
            g.commitPartial(keccak256(abi.encode("c", i)));
        }
    }

    /// With governance == address(0) the emergency exit is disabled for any caller/phase.
    function test_emergencyAbort_disabledWhenNoGovernance() public {
        vm.prank(governance);
        vm.expectRevert(SealedTally.EmergencyExitDisabled.selector);
        tally.emergencyAbort(); // setUp tally was deployed with governance off
    }

    /// Only governance may abort; the issuer/members/outsiders cannot.
    function test_emergencyAbort_onlyGovernance() public {
        SealedTally g = _stalledGovernedTally();
        vm.warp(block.timestamp + ABORT_TIMEOUT);
        vm.prank(issuer);
        vm.expectRevert(SealedTally.NotGovernance.selector);
        g.emergencyAbort();
    }

    /// Governance cannot abort before the timeout elapses.
    function test_emergencyAbort_beforeTimeoutReverts() public {
        SealedTally g = _stalledGovernedTally();
        vm.prank(governance);
        vm.expectRevert(SealedTally.TimeoutNotElapsed.selector);
        g.emergencyAbort();
    }

    /// The Open phase is not abortable (the issuer alone decides when to open).
    function test_emergencyAbort_openPhaseNotAbortable() public {
        SealedTally g = new SealedTally(issuer, members, governance, ABORT_TIMEOUT);
        vm.warp(block.timestamp + ABORT_TIMEOUT * 10);
        vm.prank(governance);
        vm.expectRevert(SealedTally.WrongPhase.selector);
        g.emergencyAbort();
    }

    /// Happy path: governance aborts a stalled opening after the timeout; the tally becomes
    /// terminal Aborted and no further commit/reveal/finalize is possible.
    function test_emergencyAbort_rescuesStalledOpening() public {
        SealedTally g = _stalledGovernedTally();
        vm.warp(block.timestamp + ABORT_TIMEOUT);

        vm.prank(governance);
        g.emergencyAbort();

        (,, uint8 phase,) = g.tally();
        assertEq(phase, uint8(4), "phase should be Aborted");

        // Terminal: the missing member committing now, or anyone finalizing, reverts.
        vm.prank(members[K - 1]);
        vm.expectRevert(SealedTally.WrongPhase.selector);
        g.commitPartial(keccak256("late"));

        vm.prank(governance);
        vm.expectRevert(SealedTally.WrongPhase.selector);
        g.emergencyAbort(); // cannot abort twice (terminal)
    }

    /// No outcome suppression: if ALL k partials are revealed and the result decodes in
    /// range, emergencyAbort() FINALIZES the honest result instead of aborting -- governance
    /// cannot wait, compute an unfavorable-but-valid result, and abort it.
    function test_emergencyAbort_finalizesFullyRevealed_noSuppression() public {
        SealedTally g = new SealedTally(issuer, members, governance, ABORT_TIMEOUT);
        bytes32[] memory seeds = new bytes32[](1);
        seeds[0] = keccak256("gf0");
        vm.startPrank(issuer);
        g.contribute(seeds[0], encB(77, seeds[0]));
        g.startReveal();
        vm.stopPrank();

        uint256[] memory parts = memberPartials(seeds);
        bytes32 iid = g.instanceId();
        bytes32 snap = g.snapshotDigest();
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            g.commitPartial(keccak256(abi.encode(iid, snap, uint8(i + 1), parts[i], salt(i))));
        }
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            g.revealPartial(parts[i], salt(i));
        }

        // All revealed but finalize() not yet called; warp past the timeout, governance acts.
        vm.warp(block.timestamp + ABORT_TIMEOUT);
        vm.prank(governance);
        g.emergencyAbort();

        (,, uint8 phase, uint16 result) = g.tally();
        assertEq(phase, uint8(3), "must be Finalized, not Aborted");
        assertEq(result, 77, "the determined valid result must be recorded, not suppressed");
    }

    /// The other fully-revealed branch: a malicious member reveals a commitment-matching but
    /// CORRUPTED partial so the aggregate decodes > MAX_RESULT. finalize() reverts
    /// DecodeOutOfRange (genuinely stuck), and governance can then emergencyAbort() it.
    function test_emergencyAbort_abortsCorruptedFullyRevealed() public {
        SealedTally g = new SealedTally(issuer, members, governance, ABORT_TIMEOUT);
        bytes32[] memory seeds = new bytes32[](1);
        seeds[0] = keccak256("gc0");
        vm.startPrank(issuer);
        g.contribute(seeds[0], encB(77, seeds[0]));
        g.startReveal();
        vm.stopPrank();

        uint256[] memory parts = memberPartials(seeds);
        // Shift member (K-1)'s partial so the aggregate decodes to 65530 > MAX_RESULT (65025):
        // honest decodes to 77, and p' = p - DELTA*(65530-77) moves the decoded value by that.
        uint256 Q = 1 << 32;
        uint256 shift = ((1 << 16) * (65530 - 77)) % Q;
        parts[K - 1] = (parts[K - 1] + Q - shift) % Q;

        bytes32 iid = g.instanceId();
        bytes32 snap = g.snapshotDigest();
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            g.commitPartial(keccak256(abi.encode(iid, snap, uint8(i + 1), parts[i], salt(i))));
        }
        for (uint256 i = 0; i < K; i++) {
            vm.prank(members[i]);
            g.revealPartial(parts[i], salt(i));
        }

        // Fully revealed but decode is out of range: finalize() reverts (genuinely stuck).
        vm.expectRevert(SealedTally.DecodeOutOfRange.selector);
        g.finalize();

        // Governance aborts the corrupted, unfinalizable opening after the timeout.
        vm.warp(block.timestamp + ABORT_TIMEOUT);
        vm.prank(governance);
        g.emergencyAbort();
        (,, uint8 phase,) = g.tally();
        assertEq(phase, uint8(4), "corrupted fully-revealed opening should be Aborted");
    }
}
