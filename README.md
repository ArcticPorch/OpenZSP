# OpenZSP

**An explainable detection engine for identity privilege risk, with its accuracy measured against labelled ground truth.**

OpenZSP looks at who can do what in an environment — humans, service accounts and AI agents — and
finds the access that makes a breach worse: dormant admin rights, over-broad service accounts,
permission-granting power held permanently, credential-stuffing bursts followed by escalation.
Every finding explains itself, cites the evidence that produced it, and states how much that
evidence can be trusted.

The name comes from **Zero Standing Privilege**: the idea that nobody should hold dangerous access
by default, and should instead request it just-in-time. The engine's job is to find the standing
access worth converting.

```
                 train   fresh v1   fresh v2
  precision     100.0%     76.5%      86.7%
  recall        100.0%    100.0%     100.0%
  specificity   100.0%     60.0%      77.8%

  82 labelled scenarios · 132 labels (81 positive, 51 negative controls) · 19 rules · 233 tests
```

> **Read these numbers carefully.** TRAIN is where thresholds are tuned, so its 100% is in-sample.
> Each **FRESH** column is a set of scenarios written *after* the rules were frozen and read
> exactly once. After the first reading, the failure *shapes* it exposed (an emergency account
> meant to sit unused, a job with little history, a department that is a minority but not absent
> among a resource's holders) were turned into new training cases in different domains. The
> rules were recalibrated on TRAIN only, and a second, new fresh set was read once. The rise from
> v1 to v2 is measured on scenarios the tuning never saw. The two remaining false alarms are named
> limits: a brand-new integration with no history, and departments with no notion of adjacent
> teams. Everything is synthetic.

---

## The core idea: low confidence is not low risk

Most scoring systems collapse *how bad something is* and *how sure we are* into one number.
OpenZSP keeps them separate. Every finding carries its own `impact`, `likelihood` and
`confidence`, and confidence is derived from the quality of the evidence behind it: how complete
the data feed is, how recently it delivered anything, and whether the engine could even classify
the permissions involved.

Here are two identities with the same risky shape — standing admin on a critical resource, never
used:

```
alice                   90.0  CRITICAL confidence 0.95
    [STALE_ACCESS] 1 standing grant(s) have never been exercised, including admin on prod_payments_db.
      -> Convert to JIT-eligible with an approval step and a short TTL, or revoke if no longer needed.
    [EXCESSIVE_PRIVILEGE] Standing admin on 1 high-value resource(s), 1 of them CRITICAL.
      -> Replace standing access with JIT elevation and an approval gate.

carol                    0.0  LOW      confidence 0.10
    [SUPPRESSED STALE_ACCESS] confidence 0.10 -- 1 standing grant(s) have never been exercised, ...
    [SUPPRESSED EXCESSIVE_PRIVILEGE] confidence 0.10 -- Standing admin on 1 high-value resource(s), ...
```

The difference is that carol's data connector stopped delivering 14 days ago. Her findings still
fire, but the engine refuses to report them as if they were trustworthy. It records them as a
**coverage gap**. Without that separation, carol would be reported either as a confident risk or as
clean — and a system that says "all clear" at the moment it goes blind is the most dangerous kind.

## How it works

```
connectors/   scenario-driven evidence, with trust metadata and two timestamps
     ↓
normalize/    evidence → identities, grants, resources, events (never drops access)
     ↓
models/       a capability taxonomy: ~11 classes of harm instead of 10,000 cloud actions
     ↓
risk/         features (what happened) + coverage (how much we saw)
              + one peer baseline (who else holds each resource)
              → 19 rules → confidence floor → probabilistic aggregation
     ↓
evaluation    findings vs ground truth → precision / recall / specificity,
              on train / holdout / fresh; threshold sweeps on train only
```

A few design decisions that shape the rest:

- **Capabilities, not permissions.** Rules reason about classes of harm (`DESTROY`,
  `MANAGE_PERMISSION`, `IMPERSONATE`, …). A cloud's action names are mapped down to those classes at
  ingestion, so a new provider needs a mapping table, not new rules. Actions the engine can't
  classify are kept as `UNKNOWN` and lower confidence instead of being dropped.
- **Traps in the test data.** Every risk type has negative controls: identities built to look
  exactly like a real finding, differing in one detail. An unused *just-in-time* grant, for
  example, is the goal state and must never be flagged.
- **Rates, not counts.** Twelve failed logins in 40 minutes and twelve across a month look the same
  as a count, and only one of them is an attack.
- **Baselines, not global numbers.** A nightly ETL job reads more in an hour than most people
  read in a year. Dormancy and bulk-read rules compare an identity to its *own* history, and
  context rules compare it to the other holders of the same resource.
- **Deterministic and cited.** No wall clock, no unseeded randomness, content-addressed evidence
  IDs. The same input always produces the same output, and every finding points at its evidence.

## Quick start

Developed and tested on Python 3.14. The only dependency is `pytest`.

```bash
git clone https://github.com/ArcticPorch/OpenZSP.git
cd OpenZSP
python -m venv venv
# Windows: venv\Scripts\activate      macOS/Linux: source venv/bin/activate
pip install pytest

python -m pytest -q              # run the 230 tests
python -m app.main               # train vs holdout vs fresh detection quality
python -m app.main --full        # whole-corpus report, including misses
python -m app.main --findings    # every identity's assessment, explained
python -m app.main --sweep CADENCE_TOLERANCE=1.0,1.25,1.5   # a tuning curve, TRAIN only
```

Run everything from the repository root.

## Learn more

**[CLAUDE.md](CLAUDE.md)** documents the architecture layer by layer, with the reasoning behind
each design decision and the conventions the tests enforce.

## Status

This is a research and learning project focused on detection engineering and calibration, with
identity attack-path and blast-radius analysis next. It runs on synthetic, labelled data; there is
no connector to a real cloud provider yet.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright 2026 Devendra Kumar.
