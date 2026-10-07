# OpenZSP

**An explainable detection engine for identity privilege risk, with its accuracy measured against labelled ground truth.**

OpenZSP looks at who can do what in an environment — humans, service accounts and AI agents — and
finds the access that makes a breach worse: dormant admin rights, over-broad service accounts,
permission-granting power held permanently, credential-stuffing bursts followed by escalation.
It also follows access *through* roles and control planes, so it can show what a compromise would
actually reach, not just what an identity holds directly. Every finding explains itself, cites the
evidence that produced it, and states how much that evidence can be trusted. It is measured on a
labelled synthetic corpus, and it reads **AWS account exports** (tested on a sample account; see
[Limitations](#limitations)).

The name comes from **Zero Standing Privilege**: the idea that nobody should hold dangerous access
by default, and should instead request it just-in-time. The engine's job is to find the standing
access worth converting.

```
                 train   fresh v1   fresh v2   fresh v3
  precision     100.0%     76.5%      86.7%      83.3%
  recall        100.0%    100.0%     100.0%      93.8%
  specificity   100.0%     60.0%      77.8%      78.6%

  127 labelled scenarios · 198 labels (116 positive, 82 negative controls) · 21 rules + 1 sequence stage · 516 tests
```

> **Read these numbers carefully.** TRAIN is where thresholds are tuned, so its 100% is in-sample.
> Each **FRESH** column is a set of scenarios written *after* the rules were frozen and read
> exactly once. After the first reading, the failure *shapes* it exposed (an emergency account
> meant to sit unused, a job with little history, a department that is a minority but not absent
> among a resource's holders) were turned into new training cases in different domains. The
> rules were recalibrated on TRAIN only, and a second, new fresh set was read once. The rise from
> v1 to v2 is measured on scenarios the tuning never saw. Its two false alarms are named limits: a
> brand-new integration with no history, and departments with no notion of adjacent teams.
> **FRESH v3** tests the identity-graph rules. It was written by an author who never opened the rule
> code (though they did see the project notes describing it), so it is more independent than v1/v2.
> Its column is the one reading under the frozen rules, after six unlabelled firings were triaged
> into labels. It exposed three shapes: a grant used and then abandoned (the miss), a long chain's
> stepping-stone roles counted as breadth, and a `login` event that cannot say whether a person or a
> pipeline signed in. The first two have since been fixed on TRAIN (an abandoned-grant rule, and
> blast radius no longer counting stepping-stones), so later v3 scores are not quoted. Everything is synthetic.

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

## Attack paths and blast radius

A permissions dump answers "what does this identity hold?". An attacker asks "what can I *become*?".
OpenZSP models the estate as a graph: a grant leads to a resource, and a role's resource leads to
the role itself, which holds grants of its own. A control plane leads to everything it governs.
Walking that graph finds access no single grant shows:

```
$ python -m app.main --paths petra
Routes to crown jewels it holds no grant on (1):
  support_crm_db  [admin, 2 hops, standing]
    petra -impersonate-> helpdesk_tier2_role =becomes=> role_helpdesk_tier2 -admin-> support_crm_db
```

petra is an outside contractor. She holds one grant, `impersonate` on a MEDIUM role, and every check
that reads grants one at a time finds nothing to report. The path is the finding, and it is also the
explanation.

- **Reach comes in tiers.** A path is only as easy as its hardest step: always-on, temporary,
  expired-but-still-attached, or needing a just-in-time approval. One JIT hop means somebody has to
  approve the path, so it is not standing access.
- **Blast radius is a sum, not a count.** Each reachable system is weighted by sensitivity ×
  exposure × what you can do there, so six read grants on dashboards don't rank like admin on
  production. The role resources a chain passes through are stepping-stones, not extra systems.
- **Choke points are verified, not guessed.** `--blast-radius` lists the single links whose removal
  closes the most routes to crown jewels. Each candidate is removed and the graph is walked again,
  so a link with a bypass never shows up as the fix:

```
$ python -m app.main --blast-radius
  adjuster_role =becomes=> role_adjuster      cuts 3: adaeze -> claims_payment_db, bruno -> ..., chiara -> ...
```

## Run it on an AWS account

The AWS connector reads the JSON an administrator can export with **read-only** CLI calls; nothing
is called live, and no credentials ever reach the tool:

```bash
aws iam get-account-authorization-details > authorization_details.json   # users, groups, roles, policies
aws configservice select-resource-config \
    --expression "SELECT arn, resourceType, tags" > config_resources.json  # every resource Config records
aws resourcegroupstaggingapi get-resources > resources.json              # tags (tagged resources only)
# plus, optionally: SCPs per OU level (scps.json), bucket/key/secret policies (resource_policies.json),
# and CloudTrail logs as delivered to S3 (cloudtrail.json); see app/connectors/aws/connector.py
python -m app.main --aws path/to/export
```

`examples/aws_sample_account/` is a small fictional account in exactly those shapes, so the whole
thing runs without AWS:

```
$ python -m app.main --aws examples/aws_sample_account --paths alice
Routes to crown jewels it holds no grant on (1):
  s3:acme-payments-ledger  [admin, 2 hops, standing]
    user/alice -impersonate-> role/DataEngineerRole =becomes=> role/DataEngineerRole -admin-> s3:acme-payments-ledger
```

What the connector does with an export:

- **Effective permissions, not attached ones.** Identity policies (with groups), resource policies,
  permission boundaries, every SCP level and explicit deny are evaluated **per action**, so
  `Allow s3:*` with `Deny s3:DeleteObject` still leaves `s3:DeleteBucket`, and it is no longer admin.
  A role is assumable only if its trust policy agrees. Each action counts only against the resource
  types AWS says it can target.
- **AWS's own classification.** All ~22,000 actions across 455 services come from AWS's
  machine-readable Service Reference (`tools/build_aws_action_levels.py`), mapped by access level,
  plus a short documented list where the level understates the harm: `sts:AssumeRole` and
  `iam:PassRole` mean *becoming someone else*, `cloudtrail:StopLogging` means *blinding the audit trail*.
- **Uncertainty is shown, not hidden.** An Allow that carries a condition (MFA, source IP) is kept
  and lowers confidence; a conditional Deny is not trusted to block. An untagged resource gets a
  documented default sensitivity, and lower confidence too.
- **The account's IAM is a control plane**, so `iam:AttachUserPolicy` on `*` reaches everything, except
  what an SCP fences off, since IAM cannot grant past an SCP.
- **No resource is invisible.** The resource list is AWS Config's inventory, plus the tagging API,
  plus every exact ARN a policy names. Each source alone misses resources, and a resource nobody
  lists is access nobody evaluates.
- **CloudTrail gives behaviour.** Console sign-ins are interactive and access-key calls programmatic,
  and an action taken through a role is attributed to the user who assumed it.

## Tuning curves

Every threshold was calibrated against the training split only. Each panel sweeps one threshold
and counts the training labels the engine gets wrong at each value. The shaded band is the range
where every label is right. The value in use sits inside that band, away from its edges, so one
new scenario can't tip it over. The chart shows the first five; the table lists all of them.

![Tuning curves: training-label errors as each calibrated threshold varies](docs/tuning_curves.svg)

| Threshold | All training labels right | In use | Bounded below by | Bounded above by |
|---|---|---|---|---|
| `CADENCE_TOLERANCE` | 0.85 – 1.75 | 1.25 | half-yearly job with short history | quarterly job that stopped |
| `MIN_CADENCE_GAPS` | only 2 | 2 | two visits 280 days apart | half-yearly job, three runs |
| `PEER_MAX_SAME_DEPT_SHARE` | 0 – 0.175 | 0.1 | marketing admin on payments | on-call SREs on billing |
| `MIN_REPORTING_CONFIDENCE` | 0.1 – 0.55 | 0.35 | dead connector | partially visible source |
| `BULK_READ_BASELINE_MULTIPLIER` | 1.7 – 6.5 | 3 | nightly ETL growth | weekly report → bulk pull |
| `DORMANT_IDENTITY_DAYS` | 47 – 160 | 90 | six weeks' parental leave | quarterly job that stopped |
| `COLD_START_DAYS` | 5 – 42 | 23 | a 4-day-old integration's backfill | a contractor six weeks in |
| `BLAST_RADIUS_MIN_RESOURCES` | 3 – 4 | 4 | one role chain to one crown jewel | a four-system agent sprawl |
| `SEQUENCE_WINDOW` | ~2 h – 38 days | 24 h | credential burst, bulk read 2 h later | the same two findings weeks apart |

Regenerate with `python -m app.main --curves docs/tuning_curves.svg` (sampled values; exact edges
lie between samples).

## How it works

```
connectors/   scenario-driven evidence, or an AWS account export (effective IAM permissions +
              CloudTrail), with trust metadata and two timestamps
     ↓
normalize/    evidence → identities, grants, resources, events (never drops access)
     ↓
models/       a capability taxonomy: ~11 classes of harm instead of 10,000 cloud actions
     ↓
graph/        identities, roles and resources as a graph; reach in four tiers, one path each
     ↓
risk/         features (what happened) + coverage (how much we saw)
              + peer baseline (who else holds each resource) + each identity's reach
              → 21 rules → cross-rule sequences → confidence floor → probabilistic aggregation
              + blast radius and choke points (remediation, not findings)
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
  IDs. The same input always produces the same output, even across processes with different hash
  seeds, and every finding points at its evidence, hop by hop for a path.

## Quick start

Developed and tested on Python 3.14. The only dependency is `pytest`.

```bash
git clone https://github.com/ArcticPorch/OpenZSP.git
cd OpenZSP
python -m venv venv
# Windows: venv\Scripts\activate      macOS/Linux: source venv/bin/activate
pip install pytest

python -m pytest -q              # run the test suite
python -m app.main               # train vs holdout vs fresh detection quality
python -m app.main --full        # whole-corpus report, including misses
python -m app.main --findings    # every identity's assessment, explained
python -m app.main --sweep CADENCE_TOLERANCE=1.0,1.25,1.5   # a tuning curve, TRAIN only
python -m app.main --paths petra    # one identity's routes to crown jewels, as readable chains
python -m app.main --blast-radius   # identities ranked by reach, then the choke points
python -m app.main --aws examples/aws_sample_account            # the whole engine on an AWS export
python -m app.main --aws examples/aws_sample_account --paths eve
```

Run everything from the repository root.

## Limitations

Stated plainly, so nothing here claims more than it shows:

- **The AWS connector is tested on a fictional sample account** and on unit tests of IAM's rules
  (explicit deny, boundaries, SCP levels, trust policies, NotAction/NotPrincipal). It has not yet
  run on a production account, nor been compared with AWS's own policy evaluation (IAM Policy
  Simulator, Access Analyzer).
- **Not modelled:** cross-account access, session policies, VPC endpoint policies, and IAM Identity
  Center permission sets. Policy **conditions are not evaluated**: a conditional Allow is kept at
  lower confidence, and a conditional Deny is not trusted to block.
- **Untagged resources get a default sensitivity** (secrets and keys HIGH, everything else MEDIUM),
  shown as lower confidence. Tags (`zsp:sensitivity`) fix it.
- **SCPs and resource policies** have to be assembled from several AWS calls into the two small
  files described in `app/connectors/aws/connector.py`.
- **Scale is untested.** Every principal is checked against every resource, which is instant for a
  small account and unmeasured for thousands of resources.
- **The measured numbers are synthetic.** The latest held-out set was written by an author who never
  opened the detection code but had read the project notes, so it is code-blind, not fully blind.
  A held-out set written by someone who has never seen the project is still to do.

## Learn more

**[CLAUDE.md](CLAUDE.md)** documents the architecture layer by layer, with the reasoning behind
each design decision and the conventions the tests enforce.

## Status

A research and learning project in two parts, both measured against labelled data: detection
engineering with calibration, and identity attack paths with blast radius, plus an AWS connector
that runs the same engine on an account export. The gap the latest held-out set exposed (grants
used and then abandoned) now has a rule built on training data only; the next fresh held-out set
would be the first to measure it.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright 2026 Devendra Kumar.
