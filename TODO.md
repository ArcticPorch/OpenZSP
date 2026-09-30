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
- [x] 19 detection rules across 7 factor types
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
- [ ] Attack-path rule: low-privilege / external identity → CRITICAL in ≤ k hops
- [ ] Choke points: edges that cut the most paths
- [ ] Graph scenarios: multi-hop positives; traps (JIT hop, broken chain, LOW-only reach)
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
