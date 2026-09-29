"""
Threshold sweeps: precision and recall as one tunable moves, on TRAIN only.

A single threshold value produces one point; a sweep produces the curve, and
the curve is what a calibration decision should be read from. The width of the
flat region where every label is right says how much margin a threshold has --
a value sitting on the edge of that plateau is one scenario away from failing,
while one in the middle has room on both sides.

**This module refuses to sweep anything but TRAIN.** Looking at a holdout curve
while choosing a value *is* tuning on the holdout -- the choice would be made
with its answers visible, and its next reading would measure memorisation.
Making that impossible here is cheaper than relying on discipline.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence

from app.connectors.synthetic import TRAIN
from app.risk import detections, scoring
from app.risk.evaluation import evaluate

# Modules whose upper-case constants a sweep may override. Rules and scoring
# read these at call time, so patching the module attribute is enough.
TUNABLE_MODULES = (detections, scoring)


@dataclass(frozen=True)
class SweepPoint:
    value: Any
    precision: float
    recall: float
    specificity: float
    false_positives: tuple[str, ...]
    false_negatives: tuple[str, ...]
    unlabelled: int

    @property
    def perfect(self) -> bool:
        return not self.false_positives and not self.false_negatives


def _owner(name: str):
    for module in TUNABLE_MODULES:
        if name.isupper() and hasattr(module, name):
            return module
    raise ValueError(
        f"{name!r} is not a tunable constant in "
        f"{', '.join(m.__name__ for m in TUNABLE_MODULES)}"
    )


def sweep(
    name: str,
    values: Sequence[Any],
    anchor_time: datetime,
    split: str = TRAIN,
) -> tuple[SweepPoint, ...]:
    """Evaluate TRAIN once per value of `name`, restoring the original after."""
    if split != TRAIN:
        raise ValueError(
            "sweeps run on TRAIN only; reading a holdout curve while choosing a "
            "value is tuning on the holdout"
        )
    module = _owner(name)
    original = getattr(module, name)
    points = []
    try:
        for value in values:
            setattr(module, name, value)
            m = evaluate(anchor_time, split=TRAIN)
            points.append(
                SweepPoint(
                    value=value,
                    precision=m.precision,
                    recall=m.recall,
                    specificity=m.specificity,
                    false_positives=tuple(
                        f"{o.subject_id}/{o.factor_type}" for o in m.false_alarms()
                    ),
                    false_negatives=tuple(
                        f"{o.subject_id}/{o.factor_type}" for o in m.misses()
                    ),
                    unlabelled=len(m.unlabelled_firings),
                )
            )
    finally:
        setattr(module, name, original)
    return tuple(points)


def plateau(points: Sequence[SweepPoint]) -> tuple[Any, Any] | None:
    """The first and last value of the widest contiguous run of perfect points."""
    best: tuple[int, int] | None = None
    start = None
    for i, p in enumerate(list(points) + [None]):
        if p is not None and p.perfect:
            start = i if start is None else start
            continue
        if start is not None:
            if best is None or (i - start) > (best[1] - best[0] + 1):
                best = (start, i - 1)
            start = None
    if best is None:
        return None
    return points[best[0]].value, points[best[1]].value


def format_sweep(name: str, points: Sequence[SweepPoint], current: Any) -> str:
    lines = [
        f"Sweep of {name} on TRAIN (current value {current})",
        "=" * 72,
        f"  {'value':>8}  {'prec':>6}  {'recall':>6}  {'spec':>6}  what changes",
    ]
    for p in points:
        what = ", ".join(
            [f"FP {x}" for x in p.false_positives] + [f"miss {x}" for x in p.false_negatives]
        )
        if p.unlabelled:
            what += f"{', ' if what else ''}{p.unlabelled} unlabelled"
        marker = "*" if p.value == current else " "
        lines.append(
            f" {marker}{p.value!s:>8}  {p.precision:6.1%}  {p.recall:6.1%}  "
            f"{p.specificity:6.1%}  {what or '-'}"
        )
    span = plateau(points)
    lines.append("")
    lines.append(
        f"  every TRAIN label correct for {span[0]} .. {span[1]}"
        if span
        else "  no value gets every TRAIN label right"
    )
    return "\n".join(lines)
