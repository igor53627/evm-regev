// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LibRegev} from "../src/LibRegev.sol";
import {RegevParameters} from "../src/RegevParameters.sol";

/// @title HiddenScore
/// @notice Example: an encrypted score accumulator with a single trusted opener.
///
/// A game issuer holds a master seed off-chain and credits players with encrypted
/// score increments. Crucially, EACH PLAYER HAS AN INDEPENDENT KEY derived from the
/// master seed:
///
///     s_player = expandSecret(keccak256(PLAYER_KEY_DOMAIN, masterSeed, player, address(this)))
///
/// Each credit is a ciphertext (a, b) where the a-vector is derived from a public
/// per-credit seed (a = PRG(ctSeed)) and never touches the chain -- only the 32-bit
/// scalar b is stored. The contract accumulates b homomorphically, so the running
/// total is committed on-chain but hidden until reveal.
///
/// Reveal: the opener reconstructs a_agg = sum of the credited a-vectors (from the
/// Credited event log), computes the single partial <a_agg, s_player>, and posts it.
/// The contract subtracts it from the accumulator and decodes the score.
///
/// WHY PER-PLAYER KEYS (this is the security argument, read it):
/// Revealing a player publishes ONE exact linear equation in that player's key
/// (<a_agg, s_player>), plus the score itself (a second, redundant near-equation).
/// Recovering an n=1536-dimensional key needs >= 1536 independent equations. With a
/// SHARED key, one instance serving many players would accumulate one equation per
/// reveal and, after ~1536 reveals, leak the key -- decrypting every unrevealed
/// player. Per-player keys make the equations land against DIFFERENT independent
/// unknowns: no key ever sees more than ~2 equations, so no key is ever within ~1534
/// of recovery. A player is also retired on reveal (the `revealed` flag blocks all
/// further credit/reveal), capping it at one reveal. This needs no noise flooding and
/// no parameter change; safety is structural.
///
/// TRUST MODEL (no committee, no threshold -- do not claim otherwise):
/// The issuer is the sole crediter and the opener is the sole opener. The opener
/// knows each player's secret and is TRUSTED both to credit honest ciphertexts and
/// to post the honest partial at reveal -- this is not a new assumption, since an
/// issuer that knows s_player can already encrypt anything. The DecodeOutOfRange
/// check below catches a class of wrong partials, NOT a dishonest opener and NOT
/// dishonest increments. For real threshold opening (k-of-k, no single trusted
/// party), see examples/SealedTally.sol.
contract HiddenScore {
    uint256 private constant Q_MASK = RegevParameters.Q_MASK;

    /// @dev Derivation tag for per-player keys (used off-chain by the issuer).
    bytes32 public constant PLAYER_KEY_DOMAIN = keccak256("HIDDENSCORE_PLAYER_KEY_v1");

    /// @dev Per-credit message bound. NOT enforced on-chain (encryption is off-chain);
    ///      documented as issuer-trust. The on-chain MAX_CREDITS cap below uses it to
    ///      guarantee the honest aggregate cannot reach p and wrap.
    uint256 public constant MAX_INCREMENT = 255;
    /// @dev On-chain cap: MAX_INCREMENT * MAX_CREDITS = 65025 < P - 1 = 65535 (F3).
    uint256 public constant MAX_CREDITS = 255;
    uint256 private constant MAX_SCORE = MAX_INCREMENT * MAX_CREDITS; // 65025

    address public immutable issuer; // sole crediter
    address public immutable opener; // sole opener (MAY equal issuer)
    bytes32 public immutable masterCommitment; // keccak256(masterSeed); provenance only, NOT enforcing

    /// @dev One storage slot: 32 + 32 + 16 + 8 = 88 bits used.
    struct PlayerState {
        uint32 bAcc; // homomorphic accumulator of ciphertext scalars (< 2^32, masked each add)
        uint32 creditCount; // number of credits (cap MAX_CREDITS)
        uint16 score; // decoded aggregate (< P), valid iff revealed
        bool revealed; // one-shot finalize flag (also "retired")
    }

    mapping(address => PlayerState) public players;
    /// @dev F5: running keccak of credited seeds, pinning the exact a-vector set AND order.
    mapping(address => bytes32) public seedDigest;
    /// @dev F6: per-instance seed uniqueness (a = PRG(ctSeed) ignores the player).
    mapping(bytes32 => bool) public usedSeed;

    event Credited(address indexed player, bytes32 ctSeed, uint32 b, uint32 creditCount, bytes32 seedDigest);
    event Revealed(address indexed player, uint16 score);

    error NotIssuer();
    error NotOpener();
    error AlreadyRevealed();
    error InvalidB();
    error SeedReused();
    error CapReached();
    error NoCredits();
    error StaleSnapshot();
    error DecodeOutOfRange();

    constructor(address _issuer, address _opener, bytes32 _masterCommitment) {
        issuer = _issuer;
        opener = _opener;
        masterCommitment = _masterCommitment;
    }

    /// @notice Credits an encrypted score increment to a player.
    /// @param ctSeed Public seed of the ciphertext's a-vector (a = PRG(ctSeed),
    ///        reconstructible off-chain; see RegevTestUtils.deriveA for the PRG).
    ///        Must be globally unique within this instance (F6).
    /// @param b Ciphertext scalar: <a, s_player> + e + Delta * m (mod q)
    function credit(address player, bytes32 ctSeed, uint256 b) external {
        if (msg.sender != issuer) revert NotIssuer();
        if (b > Q_MASK) revert InvalidB();
        if (usedSeed[ctSeed]) revert SeedReused(); // F6
        PlayerState storage st = players[player];
        if (st.revealed) revert AlreadyRevealed(); // retired: no further credit (F1 one-reveal lock)
        if (st.creditCount >= MAX_CREDITS) revert CapReached(); // F3

        usedSeed[ctSeed] = true; // F6
        bytes32 nd = keccak256(abi.encode(seedDigest[player], ctSeed)); // F5: pins set AND order
        seedDigest[player] = nd;
        st.bAcc = uint32((uint256(st.bAcc) + b) & Q_MASK);
        st.creditCount += 1;

        emit Credited(player, ctSeed, uint32(b), st.creditCount, nd);
    }

    /// @notice Reveals a player's aggregate score from the opener's single partial.
    /// @param openerPartial The opener's inner product <a_agg, s_player> (mod q)
    /// @param expectedSeedDigest The seedDigest the partial was computed against (F5);
    ///        a credit landing in between changes the digest and reverts StaleSnapshot.
    function reveal(address player, uint256 openerPartial, bytes32 expectedSeedDigest) external {
        if (msg.sender != opener) revert NotOpener();
        PlayerState storage st = players[player];
        if (st.revealed) revert AlreadyRevealed();
        if (st.creditCount == 0) revert NoCredits(); // F4: never finalize an empty player
        if (openerPartial > Q_MASK) revert InvalidB(); // F4: scalar param, no short/empty array possible
        if (seedDigest[player] != expectedSeedDigest) revert StaleSnapshot(); // F5

        uint256 diff = LibRegev.decrypt32(uint256(st.bAcc), openerPartial);
        uint256 score = LibRegev.decodeMessage(diff, RegevParameters.DELTA_SHIFT);
        if (score > MAX_SCORE) revert DecodeOutOfRange(); // F4 sanity (catches a class of wrong partials)

        st.revealed = true; // retire AFTER all validation (F4: no garbage frozen)
        st.score = uint16(score);

        emit Revealed(player, uint16(score));
    }
}
