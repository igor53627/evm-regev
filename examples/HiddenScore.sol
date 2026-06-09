// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {LibRegev} from "../src/LibRegev.sol";
import {RegevParameters} from "../src/RegevParameters.sol";

/// @title HiddenScore
/// @notice Example: an encrypted score accumulator (issuer model).
///
/// A game oracle (issuer) holds a Regev secret s off-chain and credits players with
/// encrypted score increments. Each credit is a ciphertext (a, b) where the a-vector
/// is derived from a public per-credit seed (a = PRG(ctSeed)) and never touches the
/// chain -- only the 32-bit scalar b is stored. The contract accumulates b
/// homomorphically, so the running total is committed on-chain but hidden from
/// everyone (including the player) until reveal.
///
/// Reveal: the opener(s) post partial inner products p_i = <a_agg, s_i> (computed
/// off-chain from the event log) and the contract decodes the aggregate. With a
/// committee holding additive shares s_1 + ... + s_k = s, no single party ever
/// reconstructs s.
///
/// Trust model (read before reusing this pattern):
/// - The issuer is trusted for ciphertext validity (it knows s, so it can encrypt
///   anything; that is inherent to the issuer model).
/// - Openers are trusted for correctness of partials; wrong partials decode to a
///   wrong score. ZK proofs of correct partial decryption are future work.
/// - Use a fresh key per contract instance: each reveal leaks one linear equation
///   in s per opener, so a long-lived key would degrade over many reveals.
contract HiddenScore {
    uint256 private constant Q_MASK = 0xFFFFFFFF;

    address public immutable issuer;

    struct PlayerState {
        uint256 bAcc; // homomorphic accumulator of ciphertext scalars
        uint64 creditCount;
        bool revealed;
        uint256 score;
    }

    mapping(address => PlayerState) public players;

    event Credited(address indexed player, bytes32 ctSeed, uint256 b);
    event Revealed(address indexed player, uint256 score);

    error NotIssuer();
    error AlreadyRevealed();
    error InvalidB();

    constructor(address _issuer) {
        issuer = _issuer;
    }

    /// @notice Credits an encrypted score increment to a player.
    /// @param ctSeed Public seed of the ciphertext's a-vector (a = PRG(ctSeed),
    ///        reconstructible off-chain; see RegevTestUtils.deriveA for the PRG)
    /// @param b Ciphertext scalar: <a, s> + e + Delta * m (mod q)
    function credit(address player, bytes32 ctSeed, uint256 b) external {
        if (msg.sender != issuer) revert NotIssuer();
        if (b > Q_MASK) revert InvalidB();
        PlayerState storage st = players[player];
        if (st.revealed) revert AlreadyRevealed();
        st.bAcc = (st.bAcc + b) & Q_MASK;
        st.creditCount += 1;
        emit Credited(player, ctSeed, b);
    }

    /// @notice Reveals a player's aggregate score from partial decryptions.
    /// @param partials Partial inner products <a_agg, s_i> posted by the opener(s),
    ///        where a_agg is the sum of all credited a-vectors (recomputed off-chain
    ///        from Credited events)
    function reveal(address player, uint256[] calldata partials) external {
        if (msg.sender != issuer) revert NotIssuer();
        PlayerState storage st = players[player];
        if (st.revealed) revert AlreadyRevealed();

        uint256[] memory p = partials;
        uint256 diff = LibRegev.combinePartials(st.bAcc, p);
        uint256 score = LibRegev.decodeMessage(diff, RegevParameters.DELTA_SHIFT);

        st.revealed = true;
        st.score = score;
        emit Revealed(player, score);
    }
}
