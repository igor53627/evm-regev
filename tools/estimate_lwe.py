#!/usr/bin/env python3
"""
LWE security estimator for evm-regev.

Primal uSVP estimate under the GSA heuristic (Alkim et al. 2016) with the
Core-SVP cost model, computed in log space and optimized over the number of
samples. This is a sizing heuristic; verify final parameters with the full
lattice estimator: https://github.com/malb/lattice-estimator

Default profile (TALLY-32): n=1536, q=2^32, centered binomial k=16 (sigma~2.83).
"""

import math

CLASSICAL_COST = 0.292  # Core-SVP classical exponent per blocksize unit
QUANTUM_COST = 0.265  # Core-SVP quantum exponent


def log2_delta(beta):
    """Root Hermite factor delta(beta), returned as log2."""
    d = ((math.pi * beta) ** (1.0 / beta) * beta / (2 * math.pi * math.e)) ** (
        1.0 / (2 * (beta - 1))
    )
    return math.log2(d)


def primal_beta(n, q, sigma):
    """
    Smallest BKZ blocksize beta for which the primal uSVP attack succeeds:
        sigma * sqrt(beta) <= delta^(2*beta - d - 1) * q^(m/d),  d = m + n + 1
    optimized over the number of samples m.
    """
    logq = math.log2(q)
    for beta in range(60, 2000):
        ld = log2_delta(beta)
        for m in range(n // 2, 4 * n, 16):
            d = m + n + 1
            lhs = math.log2(sigma) + 0.5 * math.log2(beta)
            rhs = (2 * beta - d - 1) * ld + (m / d) * logq
            if lhs <= rhs:
                return beta
    return None


def noise_budget(q, p, sigma, sigmas=7.5):
    """Max number of fresh-ciphertext additions before decode failure (~2^-40)."""
    margin = (q // p) // 2
    return int((margin / (sigmas * sigma)) ** 2)


def main():
    sigma = math.sqrt(16 / 2)  # centered binomial k=16
    q = 2**32
    p = 2**16

    print("=" * 64)
    print("evm-regev parameter sizing (primal uSVP, Core-SVP, GSA)")
    print(f"q = 2^32, p = 2^16, sigma = {sigma:.3f} (CBD k=16)")
    print("=" * 64)
    print(f"{'n':>6} | {'beta':>5} | {'classical':>9} | {'quantum':>8} | status")
    print("-" * 64)

    for n in [1024, 1152, 1280, 1408, 1536, 1664, 1792, 2048]:
        beta = primal_beta(n, q, sigma)
        if beta is None:
            print(f"{n:>6} | beta > 2000")
            continue
        c = CLASSICAL_COST * beta
        qb = QUANTUM_COST * beta
        status = "[PASS]" if qb >= 128 else ("[WARN]" if qb >= 100 else "[FAIL]")
        marker = "  <-- default" if n == 1536 else ""
        print(f"{n:>6} | {beta:>5} | {c:>7.1f} b | {qb:>6.1f} b | {status}{marker}")

    print()
    print(f"Noise budget at default profile: ~{noise_budget(q, p, sigma):,} additions")
    print(f"Plaintext capacity (binding constraint): aggregate < {p:,}")
    print()
    print("Verify with the full lattice estimator before production use:")
    print("  from estimator import LWE, ND")
    print("  LWE.estimate(LWE.Parameters(n=1536, q=2**32, Xs=ND.Uniform(0, 2**32-1),")
    print("               Xe=ND.CenteredBinomial(16)))")


if __name__ == "__main__":
    main()
