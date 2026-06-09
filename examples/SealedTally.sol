// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LibRegev} from "../src/LibRegev.sol";
import {RegevParameters} from "../src/RegevParameters.sol";

/// @title SealedTally
/// @notice Example: an encrypted aggregate tally opened by a real on-chain k-of-k
///         committee (no single trusted opener).
///
/// The issuer contributes encrypted values (a, b) under a single per-instance key s.
/// That key is additively shared across k committee members: s = s_1 + ... + s_k,
/// each member holding only its own s_i off-chain. To open the tally, every member
/// posts a partial p_i = <a_agg, s_i>; the contract sums them and decodes. No party
/// ever reconstructs s.
///
/// HOW FORGERY IS PREVENTED (this is the difference from a single-array reveal):
///  - msg.sender attribution: a partial for member i can only be submitted by member
///    i (the issuer cannot supply another member's partial).
///  - all-k-required: every member must submit; no single party controls the sum.
///  - commit-reveal with ALL commits locked before ANY reveal: the last revealer
///    cannot see others' partials, so it cannot choose a partial that forces the
///    decoded result to a target value. Adaptive last-submitter bias is structurally
///    impossible.
///  - binding tuple keccak256(instanceId, snapshotDigest, idx, partial, salt): blocks
///    cross-instance / cross-snapshot replay and commitment-copying across indices.
///  - snapshot freeze: startReveal freezes the accumulator and seed digest; no
///    contribution can race the opening (F5).
///
/// RESIDUAL RISK (stated, not hidden): a malicious member can commit to a GARBAGE
/// partial. It cannot AIM (commit-reveal hides others' values), so it cannot forge a
/// TARGET result, but it can corrupt the decode -- caught by finalize as a failed
/// reveal or a DecodeOutOfRange revert, or yielding a wrong-but-in-range value. n-of-n
/// has no Byzantine fault tolerance: one dishonest member corrupts the tally and one
/// absent member stalls finalize (liveness == multisig liveness). Robust correctness
/// needs ZK partial-decryption proofs (Roadmap).
contract SealedTally {
    uint256 private constant Q_MASK = RegevParameters.Q_MASK;

    uint256 public constant MAX_INCREMENT = 255;
    uint256 public constant MAX_CONTRIB = 255; // 255 * 255 = 65025 < P - 1 (F3)
    uint256 private constant MAX_RESULT = MAX_INCREMENT * MAX_CONTRIB; // 65025

    enum Phase {
        Open,
        Committing,
        Revealing,
        Finalized
    }

    address public immutable issuer; // sole contributor
    bytes32 public immutable instanceId; // binds commitments to this deployment
    uint8 public immutable k; // committee size (k-of-k)

    address[] public members;
    mapping(address => uint8) public memberIndex1; // 1-based; 0 = not a member

    /// @dev One slot: 32 + 32 + 8 + 16 = 88 bits used.
    struct Tally {
        uint32 bAcc; // accumulator (masked each add)
        uint32 contribCount; // number of contributions
        uint8 phase; // Phase
        uint16 result; // decoded tally (< P), valid iff phase == Finalized
    }

    Tally public tally;
    bytes32 public seedDigest; // F5: running digest of contributed seeds
    bytes32 public snapshotDigest; // F5: seedDigest frozen at startReveal
    uint32 public bAccSnapshot; // F5: bAcc frozen at startReveal
    mapping(bytes32 => bool) public usedSeed; // F6

    // Per-member commit-reveal (parallel arrays, length k, index = memberIndex1 - 1)
    bytes32[] public commitmentOf;
    uint256[] public partialOf;
    bool[] public committed;
    bool[] public partialRevealed; // dedicated flag (NOT a sentinel value)
    uint16 public committedCount;
    uint16 public revealedCount;

    event Contributed(bytes32 ctSeed, uint32 b, uint32 contribCount, bytes32 seedDigest);
    event RevealStarted(uint32 bAccSnapshot, bytes32 snapshotDigest);
    event PartialCommitted(address indexed member);
    event PartialRevealed(address indexed member, uint256 memberPartial);
    event Finalized(uint16 result);

    error NotIssuer();
    error NotMember();
    error NotIssuerOrMember();
    error InvalidB();
    error SeedReused();
    error CapReached();
    error WrongPhase();
    error AlreadyCommitted();
    error BadReveal();
    error AlreadyRevealed();
    error IncompletePartials();
    error NoContributions();
    error DecodeOutOfRange();

    constructor(address _issuer, address[] memory _members) {
        issuer = _issuer;
        instanceId = keccak256(abi.encode(address(this), block.chainid));
        uint256 n = _members.length;
        require(n >= 1 && n <= 255, "k out of range");
        k = uint8(n);
        for (uint256 i = 0; i < n; i++) {
            members.push(_members[i]);
            require(memberIndex1[_members[i]] == 0, "duplicate member");
            memberIndex1[_members[i]] = uint8(i + 1);
            commitmentOf.push(bytes32(0));
            partialOf.push(0);
            committed.push(false);
            partialRevealed.push(false);
        }
        tally.phase = uint8(Phase.Open);
    }

    /// @notice Issuer contributes one encrypted value to the tally.
    function contribute(bytes32 ctSeed, uint256 b) external {
        if (msg.sender != issuer) revert NotIssuer();
        if (tally.phase != uint8(Phase.Open)) revert WrongPhase(); // F5: no contribute after snapshot
        if (b > Q_MASK) revert InvalidB();
        if (usedSeed[ctSeed]) revert SeedReused(); // F6
        if (tally.contribCount >= MAX_CONTRIB) revert CapReached(); // F3

        usedSeed[ctSeed] = true;
        seedDigest = keccak256(abi.encode(seedDigest, ctSeed)); // F5
        tally.bAcc = uint32((uint256(tally.bAcc) + b) & Q_MASK);
        tally.contribCount += 1;

        emit Contributed(ctSeed, uint32(b), tally.contribCount, seedDigest);
    }

    /// @notice Freezes the accumulator/seed snapshot and opens the commit phase.
    /// @dev Gated to issuer or any member. After this, contribute() reverts (F5).
    function startReveal() external {
        if (msg.sender != issuer && memberIndex1[msg.sender] == 0) revert NotIssuerOrMember();
        if (tally.phase != uint8(Phase.Open)) revert WrongPhase();
        if (tally.contribCount == 0) revert NoContributions(); // F4

        bAccSnapshot = tally.bAcc;
        snapshotDigest = seedDigest;
        tally.phase = uint8(Phase.Committing);

        emit RevealStarted(bAccSnapshot, snapshotDigest);
    }

    /// @notice Member commits to its partial. Reveal opens only once all k have committed.
    /// @param commitment keccak256(abi.encode(instanceId, snapshotDigest, idx, partial, salt))
    function commitPartial(bytes32 commitment) external {
        uint8 idx = memberIndex1[msg.sender];
        if (idx == 0) revert NotMember();
        if (tally.phase != uint8(Phase.Committing)) revert WrongPhase();
        uint8 i = idx - 1;
        if (committed[i]) revert AlreadyCommitted();

        committed[i] = true;
        commitmentOf[i] = commitment;
        committedCount += 1;
        if (committedCount == k) tally.phase = uint8(Phase.Revealing); // all committed -> reveal opens

        emit PartialCommitted(msg.sender);
    }

    /// @notice Member reveals its partial; checked against its commitment.
    /// @dev Only callable once committedCount == k, so no plaintext partial is visible
    ///      before every commitment is locked -> no adaptive last-submitter bias.
    function revealPartial(uint256 memberPartial, bytes32 salt) external {
        uint8 idx = memberIndex1[msg.sender];
        if (idx == 0) revert NotMember();
        if (tally.phase != uint8(Phase.Revealing)) revert WrongPhase();
        if (memberPartial > Q_MASK) revert InvalidB();
        uint8 i = idx - 1;
        if (partialRevealed[i]) revert AlreadyRevealed();

        bytes32 expect = keccak256(abi.encode(instanceId, snapshotDigest, idx, memberPartial, salt));
        if (commitmentOf[i] != expect) revert BadReveal();

        partialRevealed[i] = true;
        partialOf[i] = memberPartial;
        revealedCount += 1;

        emit PartialRevealed(msg.sender, memberPartial);
    }

    /// @notice Combines all partials over the frozen snapshot and stores the result.
    function finalize() external {
        if (tally.phase != uint8(Phase.Revealing)) revert WrongPhase();
        if (revealedCount != k) revert IncompletePartials(); // F4: all partials present

        uint256[] memory partials = partialOf; // copy storage -> memory for the library call
        uint256 diff = LibRegev.combinePartials(uint256(bAccSnapshot), partials); // SNAPSHOT, not live bAcc (F5)
        uint256 m = LibRegev.decodeMessage(diff, RegevParameters.DELTA_SHIFT);
        if (m > MAX_RESULT) revert DecodeOutOfRange(); // F4 sanity

        tally.result = uint16(m);
        tally.phase = uint8(Phase.Finalized); // finalize ONLY on full success (F4)

        emit Finalized(uint16(m));
    }

    function memberCount() external view returns (uint256) {
        return members.length;
    }
}
