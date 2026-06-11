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
///
/// OPTIONAL EMERGENCY EXIT: pass a non-zero `governance` address (a multisig / DAO /
/// timelock) and a `revealTimeout` at deploy to enable emergencyAbort(). After the timeout
/// elapses on a stalled opening (Committing/Revealing), governance can move the tally to a
/// terminal Aborted state -- turning a silent permanent stall into an explicit, observable
/// dead-end (then redeploy). It can only KILL a stalled opening, never produce a result, so
/// it adds no forgery power. Pass governance = address(0) to keep the pure k-of-k model
/// (stall == redeploy-only). Because members are immutable, this is abort-and-redeploy, not
/// in-place recovery.
contract SealedTally {
    uint256 private constant Q_MASK = RegevParameters.Q_MASK;

    uint256 public constant MAX_INCREMENT = 255;
    uint256 public constant MAX_CONTRIB = 255; // 255 * 255 = 65025 < P - 1 (F3)
    uint256 private constant MAX_RESULT = MAX_INCREMENT * MAX_CONTRIB; // 65025

    enum Phase {
        Open,
        Committing,
        Revealing,
        Finalized,
        Aborted // terminal: a stalled opening was emergency-aborted (no result)
    }

    address public immutable issuer; // sole contributor
    bytes32 public immutable instanceId; // binds commitments to this deployment
    uint8 public immutable k; // committee size (k-of-k)

    /// @dev OPTIONAL emergency-exit authority (a multisig / DAO / timelock address). When
    ///      set, governance may emergencyAbort() a stalled opening after revealTimeout. When
    ///      zero, the emergency exit is DISABLED and a stalled tally is recoverable only by
    ///      redeploying (the original honest k-of-k == multisig liveness model).
    address public immutable governance;
    /// @dev Seconds after startReveal() before governance may abort a stalled opening.
    ///      Only meaningful when governance != address(0).
    uint64 public immutable revealTimeout;

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
    uint64 public revealStartedAt; // block.timestamp of startReveal (emergency-exit clock)
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
    event Aborted(address indexed by);

    error NotIssuer();
    error NotMember();
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
    error NotGovernance();
    error EmergencyExitDisabled();
    error TimeoutNotElapsed();

    constructor(address _issuer, address[] memory _members, address _governance, uint64 _revealTimeout) {
        // Zero issuer would permanently brick contribute()/startReveal() (no caller can
        // be address(0)), leaving the instance stuck in Open forever.
        require(_issuer != address(0), "zero issuer address");
        // Emergency exit is opt-in: a non-zero governance enables emergencyAbort() after the
        // timeout; a positive timeout is then required so governance cannot abort instantly.
        // governance == address(0) => feature off (a stalled tally is recovered by redeploy).
        require(_governance == address(0) || _revealTimeout > 0, "timeout required");
        governance = _governance;
        revealTimeout = _revealTimeout;
        issuer = _issuer;
        instanceId = keccak256(abi.encode(address(this), block.chainid));
        uint256 n = _members.length;
        // k-of-k committee with k >= 2: k == 1 would be a single member holding all of
        // s (a single trusted opener that can forge), which this example explicitly is not.
        require(n >= 2 && n <= 255, "k out of range");
        k = uint8(n);
        for (uint256 i = 0; i < n; i++) {
            // The committee must be disjoint from the issuer. The issuer knows the full
            // secret s, so an issuer that also held a share could unilaterally forge the
            // finalized result (commit-reveal gives no protection -- the forging partial is
            // precomputable from s + its own share). Enforced, not just assumed.
            require(_members[i] != address(0), "zero member address");
            require(_members[i] != _issuer, "issuer cannot be a member");
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
    /// @dev Issuer-only: the sole contributor signals "done contributing". Letting a
    ///      member start the reveal would let it freeze early (after one contribution)
    ///      and finalize a silently-incomplete tally. If the issuer never starts the
    ///      reveal, that is the same liveness case as the issuer declining to open.
    ///      After this, contribute() reverts (F5).
    function startReveal() external {
        if (msg.sender != issuer) revert NotIssuer();
        if (tally.phase != uint8(Phase.Open)) revert WrongPhase();
        if (tally.contribCount == 0) revert NoContributions(); // F4

        bAccSnapshot = tally.bAcc;
        snapshotDigest = seedDigest;
        revealStartedAt = uint64(block.timestamp); // starts the emergency-exit clock
        tally.phase = uint8(Phase.Committing);

        emit RevealStarted(bAccSnapshot, snapshotDigest);
    }

    /// @notice Member commits to its partial. Reveal opens only once all k have committed.
    /// @param commitment keccak256(abi.encode(instanceId, snapshotDigest, idx, partial, salt))
    /// @dev SALT MUST be >= 128-bit uniformly random and kept secret until reveal. The
    ///      committed `partial` is only ~32 bits, so the salt is the ONLY hiding entropy;
    ///      a predictable/low-entropy salt lets another member brute-force the partial
    ///      (~2^32 keccak) before reveal and defeat the no-adaptive-bias guarantee.
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

    /// @notice OPT-IN emergency exit: governance may abort a STALLED opening after the
    ///         timeout, moving the tally to the terminal Aborted state.
    /// @dev k-of-k has no Byzantine fault tolerance: one absent / lost-key / self-bricked
    ///      member stalls the commit-reveal forever, and without this the instance is
    ///      silently stuck and indistinguishable from in-progress. This converts that into an
    ///      explicit, observable dead-end so off-chain parties stop waiting and redeploy.
    ///
    ///      It NEVER produces a result, so it cannot forge or bias a tally -- the only power
    ///      it grants is to KILL a stalled (Committing/Revealing) opening once revealTimeout
    ///      has elapsed since startReveal. Because committee membership is immutable, this is
    ///      an abort (redeploy to retry), not an in-place recovery: a permanently-lost member
    ///      cannot be replaced here. The Open phase is intentionally NOT abortable -- the
    ///      issuer alone decides when to open, and a long contribution window is legitimate.
    function emergencyAbort() external {
        if (governance == address(0)) revert EmergencyExitDisabled();
        if (msg.sender != governance) revert NotGovernance();
        uint8 ph = tally.phase;
        if (ph != uint8(Phase.Committing) && ph != uint8(Phase.Revealing)) revert WrongPhase();
        if (block.timestamp < uint256(revealStartedAt) + revealTimeout) revert TimeoutNotElapsed();

        tally.phase = uint8(Phase.Aborted);

        emit Aborted(msg.sender);
    }

    function memberCount() external view returns (uint256) {
        return members.length;
    }
}
