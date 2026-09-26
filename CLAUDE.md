# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Environment & commands

Python 3.14 with a local venv at `venv/`. Pytest is the only third-party dependency (there is no `requirements.txt`, `pyproject.toml`, or `pytest.ini` — pytest picks up `tests/` via rootdir defaults, and imports resolve because `app/` and `tests/` both have `__init__.py`).

```bash
./venv/Scripts/python.exe -m pytest              # full suite (run from repo root)
./venv/Scripts/python.exe -m pytest -q tests/test_features.py
./venv/Scripts/python.exe -m pytest -q tests/test_features.py::test_permissions_extraction
```

Always invoke pytest as `python -m pytest` from the repo root — `app.*` imports depend on the root being on `sys.path`.

## Learning guide — keep it current

`docs/LEARNING_GUIDE.md` is the user's primary way of learning this project: architecture, the reasoning behind each decision, the bugs found, what's done and what's next. **Any change that alters the project must update it in the same piece of work** — the header stats, the rule table (§5.8), corpus/split details (§6), a new entry in §8 for any bug worth learning from, a new row in the history (§9), fresh numbers in §10 copied from `python -m app.main` / `--full`, and the roadmap (§11). Treat a stale guide as a bug. §15 of the guide lists exactly what to touch.

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
app/risk/detections.py 15 concrete rules across all 7 factor types
      ↓
app/risk/scoring.py    confidence, probabilistic aggregation, every tunable
      ↓
app/risk/engine.py     RiskEngine → IdentityResult (assessment + suppressed)
      ↓
app/risk/models.py     risk vocabulary + validated output DTOs
      ↓
app/risk/evaluation.py scores findings against ground truth → precision/recall
```

```bash
./venv/Scripts/python.exe -m app.main             # train vs holdout
./venv/Scripts/python.exe -m app.main --full      # whole-corpus detail
./venv/Scripts/python.exe -m app.main --train     # calibration detail
./venv/Scripts/python.exe -m app.main --holdout   # holdout detail
./venv/Scripts/python.exe -m app.main --findings  # per-identity assessments
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

The corpus is **37 scenarios / 62 labels, 45 positive and 17 negative**, sized so a single miss moves recall by ~4 points rather than ~12. `tests/test_corpus.py` enforces that: minimum positive count, a negative-control share between 20% and 50%, and both polarities per factor type. Negative controls are not optional decoration — a rule that fires unconditionally scores perfect recall on an all-positive set, so they are the only thing that makes precision computable.

Several scenarios exist as **discriminating pairs**: two identities that are identical in `IdentityFeatures` and differ only in something a naive rule ignores. `burst_then_escalation` vs `failed_logins_spread_thin` (both `failed_authentication_count == 12`, one is 18/hour and one is 0.4/day). `dormant_standing_admin` vs `recently_granted_not_yet_used` (feature-identical; only `granted_at` differs, 420 days vs 2). `service_account_sprawl` vs `read_only_analyst_wide_access` (both 6 standing grants; admin-on-production vs read-on-dashboards). `stale_connector_blind_spot` vs `incomplete_but_fresh_collection` (a connector that stopped vs one that only ever saw half). Keep these pairs feature-identical — if one drifts apart it silently stops testing anything.

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
- `RuleContext` is deliberately **not** the `Estate`. A rule that can reach the whole estate grows cross-identity logic, and peer-group baselines are a different layer with different performance characteristics. Every rule stays O(1) in estate size.
- **Assessment ids are derived** from `(rule_id, subject)`, never generated, so two runs over identical evidence produce byte-identical, diffable assessments — the same reproducibility guarantee `content_id` gives evidence.
- `rule_id` is authored and versioned (`"stale_standing_access.v1"`), not derived from the class name: renaming a class must not change ids already stored in assessments.

### Detection quality, and the train/holdout split

`Scenario.split` is `TRAIN` (24 scenarios, 46 labels) or `HOLDOUT` (13 scenarios, 16 labels). Membership is **declared per scenario, never shuffled**: a random split would move every run, so a metric could improve purely because the seed changed and yesterday's number would be unreproducible.

```
                 train    holdout       gap
  precision     100.0%     100.0%     +0.0%
  recall         91.7%     100.0%     +8.3%
  specificity   100.0%     100.0%     +0.0%
```

Whole corpus: precision 100%, recall 93.3%, F1 96.6%, 17/17 negative controls held, **zero unlabelled firings**.

**The holdout is contaminated today and its number should not be quoted.** The rules were authored before the split existed, with every scenario visible, so nothing here was genuinely held out. The machinery's value starts from the *next* calibration cycle. The current +8.3% gap is noise, not evidence of generalisation — on 9 positive labels, one miss moves holdout recall by 11 points, which is why a 100% reading means very little.

**The discipline no test can enforce:** tune against TRAIN, report HOLDOUT, and never move a threshold because a holdout number looked bad. The moment you do, the holdout is training data and its next reading is worthless. `test_detection_meets_calibration_floors` is therefore measured on TRAIN only — a floor held against the holdout would convert it into training data the first time someone edited a threshold to make the test pass. Floors: 0.90 precision / 0.85 recall / 1.00 specificity. Raise them when detection genuinely improves; never lower one to make a change pass.

`tests/test_split.py` guards the rest: the splits partition cleanly, **no subject appears in both halves** (leakage would teach the holdout answer directly), the holdout carries both polarities and spans ≥4 factor types, and a per-split score agrees pair-for-pair with the whole-corpus score. That last one rests on scenario independence — already asserted — which is what makes evaluating a subset sound rather than an artifact of what got left out.

Three labelled findings deliberately do not fire, pinned by `test_known_misses_are_exactly_the_documented_ones` so the set cannot drift silently:

- `oscar / CONTEXT_MISMATCH` — needs peer-group baselines, deferred on purpose.
- `frank / EXCESSIVE_PRIVILEGE` and `agent_ops / EXCESSIVE_PRIVILEGE` — privilege that is broad or long-lived but not privileged-on-critical, which the current rule cannot reach.

**Unlabelled firings are not counted as false positives.** A firing on a pair the corpus never labelled is reported in its own bucket and must be triaged into ground truth over time; precision is an upper bound while any remain. Counting them as errors would understate precision, ignoring them would overstate it. Note the selection bias: unlabelled firings are surfaced *by* the engine, so a detection it misses entirely never gets proposed as a label. That asymmetry is another argument for a held-out split.

### Confidence and suppression

A finding below `MIN_REPORTING_CONFIDENCE` (0.35) is **suppressed, not reported** — and carried on `IdentityResult.suppressed` rather than dropped. A finding we cannot trust is a coverage gap, not a low-risk finding, and shipping it as an alert spends the operator's attention on our own blind spot. An engine that silently discarded them could not tell an operator the difference between "nothing to see" and "we cannot see".

`confidence_from_coverage` is a **product, not a mean**: partial feed, misattributed principal, unreliable source and dead connector are independent ways of being wrong, and any one is sufficient to make the conclusion unsafe. Averaging lets three good factors rescue one fatal one — the exact arithmetic that reports "all clear" while blind.

Freshness decays exponentially (7-day half-life) rather than cliff-edging, so a rule firing at 6.9 days and vanishing at 7.1 can't happen; that discontinuity is impossible to calibrate against.

Note `carol` and `priya` both carry a deliberately unexercised grant. Without it every rule declined on them for unrelated reasons and the negative controls passed *by accident* — the suppression path was never exercised end to end. `test_blind_spot_findings_are_suppressed_not_silently_dropped` asserts `suppressed` is non-empty for exactly that reason.

### Rule conventions

- Thresholds live in module constants at the top of `detections.py`, so calibration is a diff against one block.
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
