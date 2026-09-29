# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Start here

1. **Read `TODO.md`.** It is the working plan. Work proceeds item by item in its order; tick each item (`- [x]`) in the same commit that completes it, and add new items there rather than anywhere else.
2. **Current phase: graph connectivity & blast radius** (TODO "Next"). Detection & calibration is finished; its parked items stay parked unless the user asks. **JIT access is out of scope** for this project.
3. **Do not read or edit the learning guide.** It was frozen on 2026-09-29 as a personal record, lives outside the repo, and must never be updated, recreated or committed. Do not use it for to-dos.
4. Keep `README.md` headline numbers/counts in step with `python -m app.main` whenever they change; it must not link to any learning guide.
5. Commit/push only when the user asks. Commit messages end with the co-author line used in `git log`.

## Environment & commands

Python 3.14 with a local venv at `venv/` (Windows). Pytest is the only third-party dependency (there is no `requirements.txt`, `pyproject.toml`, or `pytest.ini` — pytest picks up `tests/` via rootdir defaults, and imports resolve because `app/` and `tests/` both have `__init__.py`). Run everything from the repo root. The commands below work in Git Bash; in PowerShell/cmd use `venv\Scripts\python.exe`.

```bash
./venv/Scripts/python.exe -m pytest -q           # full suite (~30 s)
./venv/Scripts/python.exe -m pytest -q tests/test_features.py
./venv/Scripts/python.exe -m pytest -q tests/test_features.py::test_permissions_extraction
./venv/Scripts/python.exe -m app.main            # train vs holdout vs fresh
```

Always invoke pytest as `python -m pytest` from the repo root — `app.*` imports depend on the root being on `sys.path`.

## Architecture

OpenZSP scores the risk of identities (human, service, and AI-agent) holding permissions on resources. The design is a one-directional pipeline with strict layer separation:

```
app/connectors/        sources behind one protocol   SyntheticConnector (scenario-driven)
      ↓  yields Evidence
app/evidence/          the envelope + trust metadata  Evidence, EvidenceQuality, SourceRef, RecordKind
      ↓
app/normalize/         Evidence → domain objects      Normalizer → Estate (+ provenance index)
      ↓
app/models/            domain facts        Identity, Permission, Resource, Event (+ their enums)
      ↓
app/risk/features.py   FeatureExtractor → IdentityFeatures   (measurements only)
app/risk/coverage.py   CoverageAnalyzer → CoverageSummary    (how much we saw)
      ↓
app/risk/rules.py      Rule protocol, RuleContext, RuleOutcome (the contract)
app/risk/baselines.py  PeerBaseline — the one cross-identity pre-pass, built once per estate
app/risk/detections.py 19 concrete rules across all 7 factor types
      ↓
app/risk/scoring.py    confidence, probabilistic aggregation, every tunable
      ↓
app/risk/engine.py     RiskEngine → IdentityResult (assessment + suppressed)
      ↓
app/risk/models.py     risk vocabulary + validated output DTOs
      ↓
app/risk/evaluation.py scores findings against ground truth → precision/recall
app/risk/calibration.py threshold sweeps, TRAIN only
```

```bash
./venv/Scripts/python.exe -m app.main             # train vs holdout vs fresh
./venv/Scripts/python.exe -m app.main --full      # whole-corpus detail
./venv/Scripts/python.exe -m app.main --train     # calibration detail
./venv/Scripts/python.exe -m app.main --holdout   # holdout detail (contaminated)
./venv/Scripts/python.exe -m app.main --fresh     # fresh detail -- read once per cycle
./venv/Scripts/python.exe -m app.main --findings  # per-identity assessments
./venv/Scripts/python.exe -m app.main --sweep CADENCE_TOLERANCE=1.0,1.25,1.5   # TRAIN-only curve
```

The pipeline is connected end to end — `test_pipeline_reaches_feature_extraction` runs connector → normalizer → features with no hand-built fixtures. `app/risk/models.py` defines the *output* contract the unwritten layers must produce (`RiskAssessment`, `RiskFactorAssessment`, `RiskSubject`).

### Layer dependency rule

`app/common/validation.py` → `app/evidence/` → `app/models/` → `app/risk/`. The arrow never points backwards. `Evidence` and `EvidenceQuality` live in `app/evidence/`, **not** in `app/risk/models.py`, because source reliability and integrity are ingestion concerns. `app/connectors/synthetic.py` refers to risk factor types as plain strings rather than importing `RiskFactorType`, to keep ingestion free of a risk dependency; a test asserts those strings are valid enum values.

### Evidence layer

`Evidence` is both the raw-record envelope and the citation target that `RiskFactorAssessment.evidence_ids` points at — there is no separate `RawRecord` type.

- **Bitemporal.** `observed_at` (when the fact was true) and `collected_at` (when the pipeline learned it) are separate. Derived facts only: `age_at(t)`, `staleness_at(t)`, `collection_lag`. Never store a computed freshness score on the record — it would freeze an opinion that expires. Scoring derives freshness from age at evaluation time.
- `collected_at < observed_at` is **not** rejected; clock skew is normal and dropping such records loses real data.
- **IDs are content-addressed** via `content_id()`, which excludes `collected_at` so re-collecting an unchanged fact does not mint a new ID. This gives free dedup and reproducible assessments.
- `record_kind` is on the envelope, not in the payload, so streams can be filtered and dispatched without parsing.

`EvidenceConnector` is a `Protocol`, not an ABC — connectors satisfy it structurally and never import engine internals. `collect()` returns an `Iterator`; do not materialize lists inside a connector. Note `@runtime_checkable` only checks method *names*, not signatures.

### Synthetic connector

`SyntheticConnector` is a real connector, not a stub, and is the peer of any future AWS reader. Its data is **scenario-driven**: each `Scenario` carries `ExpectedFinding` ground truth, so the generator doubles as a labelled test set for measuring detection. `should_fire=False` marks a negative control (e.g. `active_admin_justified`) — "did not fire" is a tested outcome.

The corpus is **82 scenarios / 132 labels, 81 positive and 51 negative**, sized so a single miss moves recall by ~4 points rather than ~12. `tests/test_corpus.py` enforces that: minimum positive count, a negative-control share between 20% and 50%, and both polarities per factor type. Negative controls are not optional decoration — a rule that fires unconditionally scores perfect recall on an all-positive set, so they are the only thing that makes precision computable.

Several scenarios exist as **discriminating pairs**: two identities that are identical in `IdentityFeatures` and differ only in something a naive rule ignores. `burst_then_escalation` vs `failed_logins_spread_thin` (both `failed_authentication_count == 12`, one is 18/hour and one is 0.4/day). `dormant_standing_admin` vs `recently_granted_not_yet_used` (feature-identical; only `granted_at` differs, 420 days vs 2). `service_account_sprawl` vs `read_only_analyst_wide_access` (both 6 standing grants; admin-on-production vs read-on-dashboards). `active_admin_justified` vs `admin_on_medium_internal_tool` (bob vs ines: same standing admin, same usage; CRITICAL vs MEDIUM resource — the TRAIN-side trap on the privilege rule's sensitivity line). `stale_connector_blind_spot` vs `incomplete_but_fresh_collection` (a connector that stopped vs one that only ever saw half). The 2026-09-29 pairs each turn on context outside the feature vector: `agent_ops` vs `agent_intake` (same five grants; a month apart vs one afternoon), `otto` vs `pablo` (standing read on CRITICAL; secret store vs database), `svc_quarterly_recon` vs `svc_semiannual_audit` (silence judged against the identity's own rhythm), `ravi` vs `svc_nightly_etl` (80 reads in 40 minutes; first time vs every night), `oscar` vs `sonia` (who else holds the resource). Keep these pairs feature-identical — if one drifts apart it silently stops testing anything.

Every `RiskFactorType` now has both a positive label and a negative control; `test_corpus.py` asserts that with no exemptions, so a new factor type cannot be claimed as covered until both exist.

Determinism is load-bearing: no `datetime.now()` and no unseeded randomness. Time comes from an explicit `anchor_time`; scenario RNG is seeded from the **scenario name alone**, deliberately not from `seed`, so labelled fixtures never drift when `seed` (which exists only to vary unlabelled filler volume) changes.

### Coverage, and the scoring model

Scoring is **rules carrying their own confidence**, aggregated probabilistically — deliberately not a weighted sum over dimensions. A weighted sum collapses "how bad" and "how sure are we" into one number, and so cannot report *low confidence* as distinct from *low risk*. That distinction is the entire point of `stale_connector_blind_spot`, so a weighted sum structurally fails the corpus. It also leaves `impact`/`likelihood`/`confidence` on `RiskFactorAssessment` half-unused; those three fields are the output contract voting for this design.

`CoverageSummary` answers "how much of what this identity did did we actually see?", which `IdentityFeatures` deliberately cannot. It is interpretation-free in the same way — proportions, counts, elapsed days, never a trust score. Turning `min_completeness=0.4` into a confidence multiplier is a scoring decision with a tunable decay curve.

- **Quality aggregates by minimum, not mean.** Nine perfect records plus one at `completeness=0.4` averages to ~0.94, which reads healthy while describing an estate we are partly blind to. Means are carried alongside for rules that want them.
- **An identity with no evidence gets 0.0, not 1.0.** Absence of evidence is not evidence of absence; a default of 1.0 asserts perfect knowledge of something never observed.
- **Three staleness signals, not one.** `collection_staleness_days` (newest collection) is optimistic and will read 0.0 for an identity we have gone blind on, because a directory snapshot keeps refreshing while the event stream behind it dies. `max_collection_staleness_days` is the weakest link. `activity_collection_staleness_days` is the one a dormancy rule must use.
- `EvidenceIndex` is a `Protocol` that `Estate` satisfies structurally, so `app/risk/` never imports `app/normalize/` just to read a citation.

### The rule contract

- A **non-finding is a first-class result**, not `None` — `should_fire=False` controls need "ran and declined" to be representable. `RuleOutcome` rejects `fired=False` carrying scores, a description, a subject, or evidence ids.
- `RuleContext` is deliberately **not** the `Estate`. A rule that can reach the whole estate grows cross-identity logic. Every rule stays O(1) in estate size; the one cross-identity fact (`peers`, a precomputed `PeerBaseline`) is read by key.
- **Assessment ids are derived** from `(rule_id, subject)`, never generated, so two runs over identical evidence produce byte-identical, diffable assessments — the same reproducibility guarantee `content_id` gives evidence.
- `rule_id` is authored and versioned (`"stale_standing_access.v1"`), not derived from the class name: renaming a class must not change ids already stored in assessments.

### Detection quality, and the three splits

`Scenario.split` is `TRAIN` (40 scenarios, 71 labels), `HOLDOUT` (27 scenarios, 39 labels) or `FRESH` (15 scenarios, 22 labels). Membership is **declared per scenario, never shuffled**: a random split would move every run, so a metric could improve purely because the seed changed and yesterday's number would be unreproducible.

- **TRAIN** — tune here, freely.
- **HOLDOUT** — contaminated. The original held-out half (written with the rules visible) plus every *retired* FRESH set. Never quote it. It grows each cycle; that is expected.
- **FRESH** — written *after* the rules were frozen, from real-world situations in domains the rules were not tuned on, and read **once**. The only column that estimates generalisation. Currently FRESH v2. At the start of the next calibration cycle it is retired into HOLDOUT and a new FRESH set is written (ideally by someone who has not read `detections.py`).

```
                 train   holdout   fresh      gap
  precision     100.0%     95.7%   86.7%   -13.3%
  recall        100.0%    100.0%  100.0%    +0.0%
  specificity   100.0%     94.1%   77.8%   -22.2%
```

FRESH v1 (after cycle 1) read 76.5% precision / 60.0% specificity; FRESH v2 (after cycle 2) reads 86.7% / 77.8%, recall 100% both times. Whole corpus: 81 TP · 3 FP · 0 FN · 48 TN, zero unlabelled firings. **Quote FRESH, not TRAIN.**

**The discipline:** tune against TRAIN, freeze, write and read FRESH once, and never move a threshold because a FRESH number looked bad — the moment you do, FRESH is training data. When a FRESH reading reveals a failure *shape*, the fix is a new TRAIN case of that shape in a different domain (never a copy of the FRESH scenario), then the next cycle. `app/risk/calibration.py` enforces part of this: `sweep()` raises on any split but TRAIN. `test_detection_meets_calibration_floors` is measured on TRAIN only (floors 0.90 precision / 0.85 recall / 1.00 specificity; raise them when detection genuinely improves, never lower one to make a change pass). `test_no_negative_control_fires_in_train` demands zero false alarms on TRAIN only; held-out false alarms are *measurements*, pinned exactly:

- FRESH `svc_helpdesk_sync / ANOMALOUS_BEHAVIOR` — cold start: a new integration's initial backfill has no history, and `bulk_read_burst` fires on a zero baseline by design.
- FRESH `treasury_analyst / CONTEXT_MISMATCH` — flat departments: Treasury on the AP ledger is adjacent-team work, but departments are strings with no hierarchy. (A triage judgement call.)
- HOLDOUT `breakglass_root / STALE_ACCESS` — retired FRESH v1; its evidence carries no break-glass tag, so the engine cannot know.

`tests/test_split.py` guards the rest: the splits partition cleanly, **no subject appears in two splits**, both held-out splits carry both polarities, span ≥4 factor types and have ≥6 positives / ≥3 negatives, TRAIN keeps ≥50% of labels and FRESH ≥10%, and a per-split score agrees pair-for-pair with the whole-corpus score. That last one rests on scenario independence — and, for the peer rule, on `test_no_resource_is_shared_between_scenarios`.

There are **no known misses** (`test_known_misses_are_exactly_the_documented_ones` pins the empty set). oscar was fixed by `peer_access_outlier.v1`, agent_ops by `privilege_creep.v1`. `frank / EXCESSIVE_PRIVILEGE` was removed as a label on review (it double-counted his departure). **Never remove or flip a label because the engine misses it** — decide on what the factor type means, write the reason on the scenario, and report the metric change as a label change. Triage of an unlabelled firing follows the truth whichever way it moves the number.

The privilege rule's sensitivity line is pinned from both sides in TRAIN: bob CRITICAL fires, `hugo` HIGH fires, `ines` MEDIUM must not; `henry` LOW guards it in holdout. HIGH was a labelling decision by the user on 2026-09-29: whoever needs admin on a HIGH resource should request it JIT.

### Break-glass accounts

`Identity.is_break_glass` (optional payload field, default False) marks a designated emergency account. Staleness rules (`unused_standing_grant`, `dormant_identity`) skip it, because never being used is its designed state; **privilege rules never skip it** — standing admin on a crown jewel is still reported, and a tag anyone could set must not be able to hide that. The tag is input from the source of record, not something the engine can infer: an untagged break-glass account is judged like any other (`breakglass_root`).

### Calibration

`python -m app.main --sweep NAME=v1,v2,...` evaluates TRAIN once per value of a constant in `detections.py` or `scoring.py` and reports the widest all-correct range (the *plateau*). Two cycles have been run. Criterion, declared before sweeping: keep the current value if its distance to the nearer plateau edge is ≥ half the plateau's half-width, otherwise move to the midpoint (log scale / geometric midpoint for ratio thresholds; for integers, the value requiring more evidence).

| Threshold | All-correct on TRAIN | Value |
|---|---|---|
| `CADENCE_TOLERANCE` | 0.66 – 1.76 | 1.25 (cycle 1, from 1.5) |
| `MIN_CADENCE_GAPS` | exactly 2 | 2 (cycle 2, from 3) |
| `PEER_MAX_SAME_DEPT_SHARE` | 0 – <0.2 | 0.1 (cycle 2, from 0.25) |
| `MIN_REPORTING_CONFIDENCE` | >0.095 – 0.57 | 0.35 (kept) |
| `BULK_READ_BASELINE_MULTIPLIER` | >1.67 – 6.5 | 3 (kept) |

Each is bounded on both sides by a TRAIN label (carol/yara, growth ETL/sofia, SREs/oscar, key rotation/marta, semiannual/quarterly job). A threshold whose plateau is bounded on only one side is a guess — add the missing TRAIN case before tuning it. `tests/test_calibration.py` pins these plateaus, so an edit has to re-run the sweep.

### Baselines

Two kinds, both built so rules stay O(1):

- **Per-identity history**, computed inside a rule from `ctx.events`: `dormant_identity.v2` uses the median gap between activity *days* (threshold = max(90, 1.25 × median) once ≥2 gaps exist — it can only raise the floor); `bulk_read_burst.v1` compares this week's busiest hour of HIGH+ reads to the busiest hour before this week.
- **Cross-identity**, `app/risk/baselines.py` `PeerBaseline`: built **once per estate** by `RiskEngine.assess_estate` and passed as `RuleContext.peers`. It is resource-centric (who else holds this resource, and in which department) rather than department-centric, because departments are free-text strings shared by coincidence across scenarios, which would make a split's score depend on the rest of the corpus. `assess_identity` without a baseline leaves `peers=None` and the peer rule declines.

**Unlabelled firings are not counted as false positives.** A firing on a pair the corpus never labelled is reported in its own bucket and must be triaged into ground truth over time; precision is an upper bound while any remain. Counting them as errors would understate precision, ignoring them would overstate it. Note the selection bias: unlabelled firings are surfaced *by* the engine, so a detection it misses entirely never gets proposed as a label. That asymmetry is another argument for a held-out split.

### Confidence and suppression

A finding below `MIN_REPORTING_CONFIDENCE` (0.35) is **suppressed, not reported** — and carried on `IdentityResult.suppressed` rather than dropped. A finding we cannot trust is a coverage gap, not a low-risk finding, and shipping it as an alert spends the operator's attention on our own blind spot. An engine that silently discarded them could not tell an operator the difference between "nothing to see" and "we cannot see".

`confidence_from_coverage` is a **product, not a mean**: partial feed, misattributed principal, unreliable source and dead connector are independent ways of being wrong, and any one is sufficient to make the conclusion unsafe. Averaging lets three good factors rescue one fatal one — the exact arithmetic that reports "all clear" while blind.

Freshness decays exponentially (7-day half-life) rather than cliff-edging, so a rule firing at 6.9 days and vanishing at 7.1 can't happen; that discontinuity is impossible to calibrate against.

Note `carol` and `priya` both carry a deliberately unexercised grant. Without it every rule declined on them for unrelated reasons and the negative controls passed *by accident* — the suppression path was never exercised end to end. `test_blind_spot_findings_are_suppressed_not_silently_dropped` asserts `suppressed` is non-empty for exactly that reason.

### Rule conventions

- Thresholds live in module constants at the top of `detections.py`, so calibration is a diff against one block, and `calibration.sweep` can override them by name.
- A rule whose behaviour changes gets a new `rule_id` version (`dormant_identity.v2`); one whose *name* would now lie gets a new id (`standing_privilege_on_critical.v1` → `standing_privilege_on_high_value.v1`).
- Never derive an evidence/event id from a timestamp: under a shifted anchor it collides with a different record (`test_no_wall_clock_dependency`).
- **Rates, never raw counts**, for anything burst-shaped. `_max_in_window` is an O(n) two-pointer sweep; `failed_authentication_count` is identical (12) for a credential attack and a forgetful salesperson.
- A grant is exercised by an event the grant **actually authorises** (`GRANT_EXERCISED_BY`), not merely by touching the resource. A read does not exercise a delete grant — that bug hid julia's standing delete on a crown jewel. A successful `login` exercises any grant on that resource; leaving it out produced two substantive false positives.
- No rule special-cases a scenario. The blind-spot controls are handled entirely by the confidence floor.
- The engine catches exceptions per rule: one raising rule must not cost every finding from the rules after it.

### The features/scoring boundary

`IdentityFeatures` is deliberately interpretation-free: it holds counts, timestamps, and elapsed days, never scores, weights, or thresholds. Any judgement about what a value *means* belongs in the scoring layer, not in `features.py`. Preserve this when extending either side.

`FeatureExtractor.extract_features` is a stateless `@staticmethod` that builds an O(1) `resource_map` and makes a single pass over events. Keep new features inside that pass rather than adding extra loops.

### Normalizer

`Normalizer.normalize(evidence) -> Estate`. Three commitments, each covered by tests:

- **Never raises on bad input.** Unusable records become `NormalizationIssue` entries; the rest of the batch still normalizes. One malformed row must not sink an ingestion run.
- **Provenance survives without polluting the domain model.** Domain objects have no `evidence_id` field. `Estate` keeps a side index — `evidence_ids_for(kind, entity_id)` returns citation-ready IDs for `RiskFactorAssessment.evidence_ids`.
- **Deterministic conflict resolution.** Last-write-wins on `observed_at`, tie-broken by `source_reliability` then evidence ID. LWW is chosen for explainability over a per-field reliability-weighted merge, which would synthesize objects that existed in no single source. Losing records stay in the provenance index.

Dangling references are *retained with an issue*, not dropped: a grant pointing at an unknown resource is kept, because understating access is the one direction a privilege engine must not err in. `Event.timestamp` comes from `observed_at`, never `collected_at` — using collection time would shift a backfill into the present and trigger every recency window at once.

### Grant lifecycle

`Permission.standing: bool` was replaced by `GrantLifecycle` — `STANDING` / `TIME_BOUND` / `JIT_ELIGIBLE` / `ELEVATED` — because converting standing access to just-in-time access is the entire product thesis, and a bool cannot express the difference between "holds admin" and "may request admin, 4h TTL". `Permission` is frozen and validates its own invariants: `TIME_BOUND`/`ELEVATED` **require** `expires_at` (an expiring grant with no expiry is a standing grant lying about itself, and would inflate the very number this engine reports). Derived facts: `is_standing`, `is_expired_at(t)`, `confers_access_at(t)`.

`Identity`, `Resource`, and `Event` are still unfrozen and unvalidated — only `Permission` was upgraded. `Identity.permissions` is a mutable list.

### Exposure

`Resource.exposure: Exposure` (`INTERNAL` / `VPC_PEERED` / `PUBLIC`) and `Identity.is_external: bool` are a **second axis, not a level of sensitivity**. The risk is their product: a public marketing site is exposed and worthless, an internal payments ledger is priceless and unreachable, and neither is urgent. Collapsing the axes into one "risk level" makes the combination that actually matters unexpressible.

Exposure has an **identity side as well as a resource side**. `external_partner_critical_access` is the case that proves it: the resource is strictly internal, so every resource-side check reads clean, and the reachability comes entirely from the principal being a partner outside the IdP. A rule reading only `Resource.exposure` misses third-party access completely.

Both fields are **optional in the payload with quiet defaults** (`INTERNAL`, `False`). A source that knows nothing about tenancy or network reachability yields an internal principal on an internal resource, not a `NormalizationIssue`. The cost is real and deliberate: missing Access Analyzer data reads as safe rather than unknown. That is why `CoverageSummary` tracks completeness separately — absent enrichment should suppress confidence, not manufacture findings on every unenriched resource.

### Conventions that the tests enforce

- **All datetimes must be timezone-aware.** Naive datetimes raise `ValueError` via `_validate_tz_aware` / `_validate_tz_datetime` — both on `evaluation_time` and on every event timestamp belonging to the identity.
- **Everything is relative to `evaluation_time`**, never `datetime.now()`. Events after `evaluation_time` are skipped entirely; the 24h/7d windows are inclusive on both ends.
- **Missing resources degrade silently.** A permission or event referencing an unknown `resource_id` is counted in totals but never counted as critical — do not raise.
- **DTOs across `app/evidence/` and `app/risk/` are frozen dataclasses that self-validate in `__post_init__`,** using the shared helpers in `app/common/validation.py`. Collections are tuples (not lists/dicts) so instances stay hashable and immutable. Validation raises `TypeError` for wrong types and `ValueError` for out-of-range/empty/non-finite values — tests assert on that specific distinction. `bool` is explicitly rejected where a number is expected, and NaN/inf are rejected.
- **Score ranges:** `impact`/`likelihood` 0–10, all confidence and evidence-quality fields 0–1, `overall_score` and dimension scores 0–100.

### The capability taxonomy

`app/models/capability.py` defines **one** `Capability` enum. `Permission.action` is a `Capability`; `EventAction` keeps its own finer-grained vocabulary and exposes `.capability` / `.is_privileged`. `PRIVILEGED_CAPABILITIES` is the single source of truth, and `features.PRIVILEGED_PERMISSION_ACTIONS` / `ADMIN_EVENT_ACTIONS` both derive from it.

This replaced a `PermissionAction` enum that didn't line up with `EventAction` — **one flaw that produced two bugs**:

- `DELETE` was a privileged event but not a privileged permission, so standing delete on a crown jewel scored `privileged_permission_count == 0` until something was actually destroyed.
- `GRANT_PERMISSION` / `ASSUME_ROLE` / `REVOKE_PERMISSION` were observable as events but **unholdable as permissions**. The capability that makes every other permission reachable could not be modelled as held, only as already exercised. `standing_permission_management.v1` and the `viktor` / `wendy` pair were unrepresentable before this.

Both are pinned by regression tests in `tests/test_capability.py`. They can't recur, because there is now only one set for the two sides to read.

**Events deliberately keep a finer vocabulary than capabilities.** Which privileged thing happened matters to detection in a way it doesn't to entitlement: a revoke followed by a grant is the shape of covering tracks, and collapsing both to `MANAGE_PERMISSION` at ingestion would erase the sequence that makes it a finding.

### Normalizing a real cloud's vocabulary

**Do not extend the enum to match a provider.** AWS has 10,000+ IAM actions across 400+ services and adds more weekly; an enum of action strings would break on every release and still be useless for Entra, Okta or Snowflake. Actions number in the thousands, *classes of harm* number about a dozen and are stable across providers and years.

Reality is normalized **down** to the taxonomy at ingestion via `Capability.from_token()` — exact match, then aliases, then provider-qualified segments (`s3:DeleteObject`), then verb prefixes. A real connector should carry an explicit table rather than lean on the heuristics; AWS publishes one (the IAM Service Authorization Reference classifies every action by access level, and its "Permissions management" category hands you `MANAGE_PERMISSION` for free). Adding a third cloud is a connector plus a table, **with no rule changes** — rules are per risk-pattern, not per action.

**`UNKNOWN` must never be defaulted away.** `from_token` never raises; an unrecognised action becomes `Capability.UNKNOWN` and the grant is **retained**. The normalizer previously ran it through `_parse_enum`, which raised and turned the grant into a `NormalizationIssue` — dropping it, and so understating access, the one direction this engine must not err in. Mapping unknowns to `READ` would be worse: a silent, confident understatement.

Retention alone would be worse than dropping, so it has to cost something. `CoverageSummary.capability_coverage` reports the share of grants we could classify and feeds `confidence_from_coverage` alongside the collection factors. `unmapped_capability_grants` (yusuf) is the scenario: three of four grants opaque → coverage 0.25 → confidence 0.24 → findings suppressed. Retained, and reported as a coverage gap rather than an all-clear.

### Every privileged capability must be measured

`test_every_privileged_capability_is_measured` asserts that each member of `PRIVILEGED_CAPABILITIES` is *held* by at least one labelled subject. Vocabulary no scenario exercises is breadth recall cannot see — adding an enum member without scenarios fails this test rather than quietly inflating the taxonomy.

It has already earned its keep: it caught `IMPERSONATE` being privileged while no grant anywhere conferred it. `kwame` *exercised* assume_role but nobody *held* impersonation — the exact held-vs-exercised asymmetry the unification fixed, recurring one level up in the corpus. His grant had been flattened to `admin` because the old vocabulary had no member for "may assume other roles", which was the capability his whole scenario is about.

Capability-specific pairs, each identical but for one attribute:

| Capability | Positive | Control | Differs by |
|---|---|---|---|
| `MANAGE_PERMISSION` | `viktor` | `wendy` | lifecycle (standing vs JIT) |
| `MANAGE_IDENTITY` | `svc_helpdesk` | `zainab` | lifecycle (standing vs time-bound) |
| `MANAGE_SECURITY_CONTROL` | `svc_observability` | `tomas` | capability (tamper vs read) |
| `IMPERSONATE` | `rahul` | — | (covered by lifecycle pairs above) |

`security_control_tamper_rights` carries a point the others don't: svc_observability **actively uses** the grant, so no staleness rule fires and the finding must rest on what the grant *confers*. An engine that only reported unused grants would never surface the most dangerous permission in the estate as long as somebody kept touching it. `MANAGE_SECURITY_CONTROL` is singled out from ordinary privilege because of who it blinds — stopping the audit pipeline disables every other detection here, including the ones watching that identity, and tampering is usually visible only in the logs the tampering removes.
