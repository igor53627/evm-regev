---
id: TASK-4
title: Run the full lattice-estimator (Sage) to confirm bit-security pre-production
status: To Do
assignee: []
created_date: '2026-06-11 10:56'
labels:
  - roadmap
  - pre-production
  - security
dependencies: []
references:
  - tools/estimate_lwe.py
  - README.md
priority: high
ordinal: 4000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
tools/estimate_lwe.py uses a SIMPLIFIED GSA heuristic and reports ~148-bit classical / ~134-bit quantum at n=1536 (beta=507) for TALLY-32 (q=2^32, sigma~2.83 CBD k=16, Xs uniform mod q). The README and the script itself recommend verifying with the authoritative malb lattice-estimator before production. It needs SageMath, so it cannot run in CI (confirmed unavailable in the dev env) -- captured here as a pre-production gate.

Run (Sage):
  from estimator import LWE, ND
  LWE.estimate(LWE.Parameters(n=1536, q=2**32, Xs=ND.Uniform(0, 2**32-1), Xe=ND.CenteredBinomial(16)))
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Run the malb lattice-estimator on the TALLY-32 params in SageMath
- [ ] #2 Confirm >= 128-bit security under all attack models the estimator reports (or bump n and update RegevParameters + estimate_lwe.py + README)
- [ ] #3 Record the estimator output in README/docs as the authoritative figure
<!-- AC:END -->
