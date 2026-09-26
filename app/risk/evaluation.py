"""
Scoring the detections against ground truth.

This is the module that makes the project falsifiable. Everything else produces
findings; this decides whether they were the right ones.

A note on what is and is not counted, because it is the difference between an
honest number and a flattering one:

  * A **false positive** is a firing on a `(subject, factor)` pair the corpus
    explicitly labelled `should_fire=False`. Those are the negative controls,
    and they are the only firings we can be certain are wrong.
  * A firing on a pair the corpus says nothing about is **unlabelled**, not a
    false positive. Some are genuine detections nobody got round to labelling;
    some are noise. Counting them as errors would understate precision, and
    silently ignoring them would overstate it -- so they are reported as their
    own number and must be triaged into labels over time.

Precision computed only over labelled pairs is therefore an *upper bound*. It
is quoted alongside the unlabelled count so the bound is visible rather than
implied.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from app.connectors.synthetic import HOLDOUT, TRAIN, SyntheticConnector, scenarios_for
from app.normalize.normalizer import Normalizer
from app.risk.engine import RiskEngine


@dataclass(frozen=True)
class Outcome:
    """One labelled (subject, factor) pair and what the engine did with it."""

    subject_id: str
    factor_type: str
    should_fire: bool
    did_fire: bool
    suppressed: bool
    rationale: str

    @property
    def kind(self) -> str:
        if self.should_fire and self.did_fire:
            return "TP"
        if self.should_fire and not self.did_fire:
            return "FN"
        if not self.should_fire and self.did_fire:
            return "FP"
        return "TN"


@dataclass(frozen=True)
class DetectionMetrics:
    split: str
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    unlabelled_firings: tuple[tuple[str, str], ...]
    suppressed_firings: tuple[tuple[str, str], ...]
    outcomes: tuple[Outcome, ...]

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def specificity(self) -> float:
        """Share of negative controls correctly left alone."""
        denom = self.true_negatives + self.false_positives
        return self.true_negatives / denom if denom else 0.0

    def by_factor(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for o in self.outcomes:
            bucket = out.setdefault(
                o.factor_type, {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
            )
            bucket[o.kind] += 1
        return out

    def misses(self) -> tuple[Outcome, ...]:
        return tuple(o for o in self.outcomes if o.kind == "FN")

    def false_alarms(self) -> tuple[Outcome, ...]:
        return tuple(o for o in self.outcomes if o.kind == "FP")


def evaluate(
    anchor_time: datetime,
    engine: Optional[RiskEngine] = None,
    connector: Optional[SyntheticConnector] = None,
    split: Optional[str] = None,
) -> DetectionMetrics:
    """
    Run the pipeline over one split of the labelled corpus and score the result.

    `split=None` scores the whole corpus. Use TRAIN while calibrating and
    HOLDOUT to report, and never the reverse: the moment a threshold is moved
    because a holdout number looked bad, the holdout has become training data
    and its next reading means nothing.
    """
    connector = connector or SyntheticConnector(
        anchor_time=anchor_time, scenarios=scenarios_for(split)
    )
    engine = engine or RiskEngine()

    estate = Normalizer().normalize(connector.collect())
    results = engine.assess_estate(estate, anchor_time)

    fired: set[tuple[str, str]] = set()
    suppressed: set[tuple[str, str]] = set()
    for result in results:
        for factor in result.assessment.triggered_factors:
            fired.add((factor.subject.subject_id, factor.factor_type.value))
        for factor in result.suppressed:
            suppressed.add((factor.subject.subject_id, factor.factor_type.value))

    outcomes: list[Outcome] = []
    labelled: set[tuple[str, str]] = set()
    for label in connector.expected_findings():
        key = (label.subject_id, label.factor_type)
        labelled.add(key)
        outcomes.append(
            Outcome(
                subject_id=label.subject_id,
                factor_type=label.factor_type,
                should_fire=label.should_fire,
                did_fire=key in fired,
                suppressed=key in suppressed,
                rationale=label.rationale,
            )
        )

    counts = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for o in outcomes:
        counts[o.kind] += 1

    return DetectionMetrics(
        split=split or "all",
        true_positives=counts["TP"],
        false_positives=counts["FP"],
        false_negatives=counts["FN"],
        true_negatives=counts["TN"],
        unlabelled_firings=tuple(sorted(fired - labelled)),
        suppressed_firings=tuple(sorted(suppressed)),
        outcomes=tuple(outcomes),
    )


def format_report(m: DetectionMetrics) -> str:
    """A plain-text calibration report. The thing you actually read while tuning."""
    lines = [
        f"OpenZSP detection quality -- {m.split}",
        "=" * 58,
        f"  precision   {m.precision:6.1%}   (TP {m.true_positives} / "
        f"TP+FP {m.true_positives + m.false_positives})",
        f"  recall      {m.recall:6.1%}   (TP {m.true_positives} / "
        f"TP+FN {m.true_positives + m.false_negatives})",
        f"  F1          {m.f1:6.1%}",
        f"  specificity {m.specificity:6.1%}   (negative controls held: "
        f"{m.true_negatives}/{m.true_negatives + m.false_positives})",
        "",
        f"{'factor type':<24} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}",
        "-" * 58,
    ]
    for factor, c in sorted(m.by_factor().items()):
        lines.append(
            f"{factor:<24} {c['TP']:>3} {c['FP']:>3} {c['FN']:>3} {c['TN']:>3}"
        )

    if m.misses():
        lines += ["", "MISSES (labelled, did not fire):"]
        for o in m.misses():
            note = " [suppressed: low confidence]" if o.suppressed else ""
            lines.append(f"  - {o.subject_id} / {o.factor_type}{note}")

    if m.false_alarms():
        lines += ["", "FALSE ALARMS (negative control fired):"]
        for o in m.false_alarms():
            lines.append(f"  - {o.subject_id} / {o.factor_type}")

    if m.suppressed_firings:
        lines += ["", "SUPPRESSED for low confidence (coverage gaps, not all-clears):"]
        for subject, factor in m.suppressed_firings:
            lines.append(f"  - {subject} / {factor}")

    if m.unlabelled_firings:
        lines += [
            "",
            f"UNLABELLED FIRINGS ({len(m.unlabelled_firings)}) -- not counted as FP.",
            "Precision above is an upper bound until these are triaged into labels:",
        ]
        for subject, factor in m.unlabelled_firings:
            lines.append(f"  - {subject} / {factor}")

    return "\n".join(lines)


def compare_splits(
    anchor_time: datetime, engine: Optional[RiskEngine] = None
) -> str:
    """
    The number that actually means something: tuned-on versus never-opened.

    The gap between the two columns estimates how much of the score is
    memorisation. A small gap suggests the rules encode transferable structure;
    a large one says they were fitted to scenarios that happened to be visible.
    """
    train = evaluate(anchor_time, engine=engine, split=TRAIN)
    holdout = evaluate(anchor_time, engine=engine, split=HOLDOUT)

    def row(label, a, b):
        return "  {:<12} {:>7.1%} {:>10.1%} {:>+9.1%}".format(label, a, b, b - a)

    lines = [
        "OpenZSP detection quality -- train vs holdout",
        "=" * 58,
        "  {:<12} {:>7} {:>10} {:>9}".format("", "train", "holdout", "gap"),
        row("precision", train.precision, holdout.precision),
        row("recall", train.recall, holdout.recall),
        row("F1", train.f1, holdout.f1),
        row("specificity", train.specificity, holdout.specificity),
        "",
        "  train:   {} positive labels, {} negative controls".format(
            train.true_positives + train.false_negatives,
            train.true_negatives + train.false_positives,
        ),
        "  holdout: {} positive labels, {} negative controls".format(
            holdout.true_positives + holdout.false_negatives,
            holdout.true_negatives + holdout.false_positives,
        ),
    ]
    return "\n".join(lines)
