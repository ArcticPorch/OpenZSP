"""
Cross-rule sequences: several findings on one identity that are one incident.

Rules never see each other -- that is the contract, and it keeps each one
O(1) and testable alone. But an attack is usually several things in a row: a
burst of failed logins, then a success, then a bulk read of customer data.
Each rule sees its own piece; nobody sees the chain. This stage runs *after*
the rules, over one identity's reported findings, and links the ones whose
cited events fall close together in time.

What it links, decided with the user (2026-10-03):

* **Reported findings only.** A suppressed finding is a coverage gap, and a
  sequence built on things we cannot trust is not one we can report.
* **Event-citing findings only.** Time is read from the activity events a
  finding cites. A staleness or privilege finding cites grants -- it describes
  a state, not a moment -- so it has no place in a timeline.
* **Distinct rules, and distinct evidence.** Two pieces of evidence for the
  same rule are one stage. And a finding whose cited events are a subset of
  another stage's adds nothing: `escalation_after_failed_auth` already cites
  the failed logins `failed_auth_burst` cites, so chaining the two would link
  one piece of evidence to itself (irene, owen, svc_deploy did exactly that
  on the first run).
* **Within `detections.SEQUENCE_WINDOW`** (24 hours) of each other, chained:
  stage B joins if it starts within the window of the latest event seen so
  far in the group. `staged_intrusion` vs `same_findings_weeks_apart`.

The result is one `MULTI_STAGE_SEQUENCE` finding citing every stage's
evidence, in time order. It does not replace the stages -- each is still
reported -- and it scores the chain: impact of the worst stage, likelihood
one point above the most likely stage (the chain is evidence each stage is
not a coincidence), confidence of the *least* trusted stage (a chain is as
trustworthy as its weakest link).
"""

from datetime import datetime
from typing import Mapping, Optional, Sequence

from app.risk import detections
from app.risk.models import RiskFactorAssessment, RiskFactorType
from app.risk.rules import RuleOutcome

RULE_ID = "multi_stage_sequence.v1"
FACTOR_TYPE = RiskFactorType.MULTI_STAGE_SEQUENCE


def correlate(
    staged: Sequence[tuple[str, RiskFactorAssessment]],
    event_times: Mapping[str, datetime],
) -> Optional[RuleOutcome]:
    """
    `staged` is (rule_id, reported finding) for one identity; `event_times`
    maps a cited evidence id to the event's time. Returns the sequence finding
    for the group with the most distinct rules, or None.
    """
    cited = {}
    for rule_id, finding in staged:
        events = frozenset(e for e in finding.evidence_ids if e in event_times)
        if events:
            cited[rule_id] = (events, finding)
    # Drop a stage whose events another stage already cites in full. Ties
    # (identical evidence) keep the alphabetically first rule, deterministically.
    independent = {
        rule_id: (events, finding)
        for rule_id, (events, finding) in cited.items()
        if not any(
            other != rule_id
            and events <= other_events
            and (events != other_events or other < rule_id)
            for other, (other_events, _) in cited.items()
        )
    }
    stages = []
    for rule_id, (events, finding) in independent.items():
        times = sorted(event_times[e] for e in events)
        stages.append((times[0], times[-1], rule_id, finding))
    stages.sort(key=lambda s: (s[0], s[2]))

    window = detections.SEQUENCE_WINDOW
    groups: list[list] = []
    for stage in stages:
        if groups and stage[0] - max(s[1] for s in groups[-1]) <= window:
            groups[-1].append(stage)
        else:
            groups.append([stage])

    def distinct(group) -> int:
        return len({s[2] for s in group})

    candidates = [g for g in groups if distinct(g) >= detections.SEQUENCE_MIN_STAGES]
    if not candidates:
        return None
    group = max(candidates, key=lambda g: (distinct(g), -g[0][0].timestamp()))

    # One stage per rule, the earliest; the evidence keeps every cited record.
    first_per_rule: dict[str, tuple] = {}
    for stage in group:
        first_per_rule.setdefault(stage[2], stage)
    chain = sorted(first_per_rule.values(), key=lambda s: (s[0], s[2]))
    findings = [s[3] for s in chain]
    span_hours = (max(s[1] for s in group) - group[0][0]).total_seconds() / 3600.0

    steps = " -> ".join(f"{s[2]} ({s[0]:%Y-%m-%d %H:%M})" for s in chain)
    return RuleOutcome(
        fired=True,
        subject=findings[0].subject,
        impact=max(f.impact for f in findings),
        likelihood=min(10.0, max(f.likelihood for f in findings) + 1.0),
        confidence=min(f.confidence for f in findings),
        description=f"{len(chain)} detections form one sequence within {span_hours:.1f} hours: {steps}.",
        recommendation=(
            "Investigate as a single incident: contain the identity first, then work "
            "the stages in order."
        ),
        evidence_ids=tuple(dict.fromkeys(e for f in findings for e in f.evidence_ids)),
    )
