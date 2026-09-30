# OpenZSP — TODO

Working plan. Tick items in the same commit that completes them.

## Architecture

```
connectors → evidence → normalize → models → graph → risk (features · coverage · baselines · rules · scoring · engine) → evaluation · calibration
```

## Done

- [x] Evidence envelope, synthetic connector, normalizer, domain models
- [x] Capability taxonomy, grant lifecycle, exposure
- [x] Features, coverage, confidence-weighted scoring, suppression
- [x] 19 detection rules across 7 factor types (20 with the attack-path rule)
- [x] Peer baseline pre-pass (resource-centric)
- [x] Per-identity baselines (dormancy rhythm, bulk-read history)
- [x] Break-glass tag (excuses staleness, never privilege)
- [x] Train / holdout / fresh splits; TRAIN-only threshold sweeps
- [x] Calibration cycle 1 and 2 — FRESH v2: precision 86.7% · recall 100% · specificity 77.8%

## Next — graph connectivity & blast radius

- [x] Model roles as principals (role resource ↔ role identity)
- [x] `app/graph/`: build identity–resource graph from `Estate`
- [x] Edge types: holds (capability, lifecycle), assumes/impersonates, manages-permission (+ `Resource.governs`, gustav/hanna pair)
- [x] Reachability: BFS with hop limit, keep paths
- [x] Effective reach per identity: (resource, capability) set; standing / temporary / expired-attached / JIT-only
- [x] `standing_permission_management.v2` on effective reach — closes structural miss gustav
- [x] Blast-radius score from reachability (sensitivity × exposure weighted)
- [x] `standing_blast_radius.v2` on reachability, replacing grant count
- [x] Attack-path rule: indirect path → control of CRITICAL in ≤ k hops (any origin, per target; petra/quinn pair)
- [x] Choke points: edges that cut the most paths (verified by removal; attack + governs routes)
- [ ] Graph scenarios: multi-hop positives; traps (JIT hop, broken chain, LOW-only reach)
  - **Start here next session.** Already in TRAIN: gustav/hanna (governs), petra/quinn (role path,
    JIT-hop trap). Still needed, each as a positive + trap pair in a new domain:
    - a 3–4 hop chain (role → role → crown jewel) and one just *beyond* the hop limit — gives
      `REACH_MAX_HOPS` / `ATTACK_PATH_MAX_HOPS` their missing upper edge (both provisional at 4)
    - governs → role resource → crown jewel (becoming a role by rewriting its trust)
    - broken chain: role link to a principal with no grants / a dangling principal
    - LOW-only reach through a role (breadth without a crown jewel)
    - a role shared by several contractors, so choke-point ranking has something to rank
    - role-hidden sprawl for `standing_blast_radius.v2` (one grant onto a wide role)
  - Open question for the user: give irene / kwame / rahul's role-shaped resources real principals?
    (changes already-labelled scenarios)
- [ ] Labels + TRAIN / FRESH split for graph scenarios
- [ ] Calibrate hop limit and score thresholds (TRAIN only), read FRESH once
- [ ] CLI: `--paths <identity>`, `--blast-radius`
- [ ] Tests: graph build, reachability, path explanation, determinism
- [ ] Update README + CLAUDE.md

## Detection & calibration — parked

- [ ] Cold-start grace period for baseline rules (+ TRAIN trap)
- [ ] Hierarchical departments for peer groups
- [ ] Peer groups by identity type
- [ ] Secret-path scoping for secret access
- [ ] Sequence detections across rules
- [ ] Blind FRESH set written by someone who hasn't read the rules
- [x] Tuning-curve charts for README

## Later — real deployment

- [ ] AWS connector (IAM Service Authorization Reference mapping)
- [ ] Effective-permission evaluation (policies, boundaries, SCPs, conditions)
- [ ] Freeze + self-validate `Identity`, `Resource`, `Event`

## Out of scope

- JIT access broker
