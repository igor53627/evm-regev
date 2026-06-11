---
id: TASK-6
title: Production key-dealing ceremony + share-consistency verification
status: To Do
assignee: []
created_date: '2026-06-11 10:56'
labels:
  - roadmap
  - tooling
dependencies: []
references:
  - src/RegevTestUtils.sol
priority: medium
ordinal: 6000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
RegevTestUtils.splitSecretK is TEST/DEV ONLY: a single-seed dealer derives (and thus knows) every share, so it provides no real threshold secrecy. Production needs an off-chain dealing flow where no single party holds s -- a trusted-dealer VSS or a DKG -- plus a way for each committee member to verify its share is consistent with the issuer's encryption key before committing. This (and the leakage of <a_agg, s_i> per opening / per-instance key non-reuse) is currently outside the repo.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Specify/implement a production share-dealing flow (VSS or DKG) so no single party reconstructs s
- [ ] #2 Provide member-side share-consistency verification against the issuer's key
- [ ] #3 Document per-instance key non-reuse (reusing s across >=1536 finalized instances leaks it)
<!-- AC:END -->
