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
- [x] Graph scenarios (TRAIN): 3-hop chain / broken chain, 6-hop chain / HIGH end, governs → role / LOW only,
  role-hidden sprawl / no crown jewel, shared contractor role; hop limits → compute bounds, likelihood falls per hop
- [x] Labels + TRAIN / FRESH split for graph scenarios — FRESH v2 retired to HOLDOUT; FRESH v3 written code-blind by a subagent
- [x] Calibrate hop limit and score thresholds (TRAIN only), read FRESH once — blast gate exactly 4; FRESH v3: 100%* / 92.3% / 100%
- [x] Triage the 6 unlabelled FRESH v3 firings — 3 TP, 3 traps; triaged reading 83.3% / 93.8% / 78.6%; vesna relabelled, blast radius v3 (stepping-stones not counted)
- [x] TRAIN case for a grant used, then abandoned (FRESH v3 miss shape): marisol / nikolai — marisol a structural miss
- [x] CLI: `--paths <identity>`, `--blast-radius` (app/risk/graph_report.py)
- [x] Tests: graph build, reachability, path explanation, determinism — audit; fixed a shadowed test; corpus properties; hash-seed determinism
- [x] Update README + CLAUDE.md — graph phase wrap-up
- [ ] Next cycle: abandoned-grant rule (a grant's last use against its own rhythm) — closes marisol

## Detection & calibration — parked

- [ ] Cold-start grace period for baseline rules (+ TRAIN trap)
- [ ] Hierarchical departments for peer groups
- [ ] Peer groups by identity type
- [ ] Secret-path scoping for secret access
- [ ] Sequence detections across rules
- [ ] Blind FRESH set written by someone who hasn't read the rules (FRESH v3 is code-blind only: its author saw CLAUDE.md)
- [x] Tuning-curve charts for README

## Later — real deployment

- [ ] Event auth kind (interactive vs programmatic) — `login` cannot tell a person from a pipeline (FRESH v3 CI deployer)

- [ ] AWS connector (IAM Service Authorization Reference mapping)
- [ ] Effective-permission evaluation (policies, boundaries, SCPs, conditions)
- [ ] Freeze + self-validate `Identity`, `Resource`, `Event`

## Out of scope

- JIT access broker
