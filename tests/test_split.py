"""
Train/holdout integrity.

A held-out set only means something while it stays held out. These tests guard
the properties that keep it honest: that the split is fixed rather than
shuffled, that neither half is too small to read, that no subject appears in
both halves, and that evaluating a subset gives the same answer the subset
would have given inside the full corpus.

What no test can enforce is the discipline: tune against TRAIN, report HOLDOUT,
and never move a threshold because a holdout number looked bad. The moment you
do, the holdout is training data and its next reading is worthless.
"""

from collections import Counter
from datetime import datetime, timezone

import pytest

from app.connectors.synthetic import (
    HOLDOUT,
    SCENARIOS,
    SPLITS,
    TRAIN,
    Scenario,
    SyntheticConnector,
    scenarios_for,
)
from app.risk.evaluation import compare_splits, evaluate

ANCHOR = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)

# A holdout smaller than this cannot support a percentage: with 8 positives,
# one miss already moves recall by 12.5 points.
MIN_HOLDOUT_POSITIVES = 6
MIN_HOLDOUT_NEGATIVES = 3


def labels(split=None):
    return [f for s in scenarios_for(split) for f in s.expected]


# --- Split integrity -------------------------------------------------------


def test_every_scenario_declares_a_valid_split():
    for s in SCENARIOS:
        assert s.split in SPLITS, s.name


def test_invalid_split_is_rejected():
    with pytest.raises(ValueError):
        Scenario(
            name="x",
            description="d",
            expected=(),
            build=lambda b, r: [],
            split="validation",
        )


def test_splits_partition_the_corpus():
    train, holdout = scenarios_for(TRAIN), scenarios_for(HOLDOUT)
    assert len(train) + len(holdout) == len(SCENARIOS)
    assert not {s.name for s in train} & {s.name for s in holdout}


def test_split_membership_is_fixed_not_shuffled():
    """
    A random split would move every run, so a metric could improve purely
    because the seed changed and nobody could reproduce yesterday's number.
    """
    assert {s.name for s in scenarios_for(HOLDOUT)} == {
        s.name for s in scenarios_for(HOLDOUT)
    }
    assert scenarios_for(HOLDOUT) == scenarios_for(HOLDOUT)


def test_no_subject_appears_in_both_splits():
    """
    Leakage check.

    If one identity were labelled in both halves, tuning on the train label
    would teach the rule the holdout answer directly, and the gap between the
    two columns would understate memorisation.
    """
    train_subjects = {f.subject_id for f in labels(TRAIN)}
    holdout_subjects = {f.subject_id for f in labels(HOLDOUT)}
    assert not train_subjects & holdout_subjects


def test_holdout_is_large_enough_to_read():
    positives = [f for f in labels(HOLDOUT) if f.should_fire]
    negatives = [f for f in labels(HOLDOUT) if not f.should_fire]
    assert len(positives) >= MIN_HOLDOUT_POSITIVES, (
        f"{len(positives)} positives: one miss moves recall by "
        f"{100 / max(len(positives), 1):.0f} points"
    )
    assert len(negatives) >= MIN_HOLDOUT_NEGATIVES


def test_holdout_carries_both_polarities():
    """Precision is not computable on an all-positive holdout."""
    polarities = {f.should_fire for f in labels(HOLDOUT)}
    assert polarities == {True, False}


def test_holdout_spans_several_factor_types():
    """A holdout covering one factor measures one rule, not the engine."""
    kinds = {f.factor_type for f in labels(HOLDOUT)}
    assert len(kinds) >= 4, kinds


def test_holdout_is_a_reasonable_share():
    share = len(labels(HOLDOUT)) / len(labels())
    assert 0.2 <= share <= 0.45, share


# --- Evaluating a subset is sound ------------------------------------------


def test_scenarios_for_none_is_the_whole_corpus():
    assert scenarios_for(None) == SCENARIOS


def test_unknown_split_raises():
    with pytest.raises(ValueError):
        scenarios_for("nope")


def test_subset_records_match_the_full_corpus():
    """
    Scenario independence is what makes a per-split score comparable.

    If evaluating a subset produced different records than those scenarios
    produce inside the full corpus, a split score would measure what got left
    out rather than the rules.
    """
    subset = {
        e.id
        for e in SyntheticConnector(
            anchor_time=ANCHOR, scenarios=scenarios_for(HOLDOUT)
        ).collect()
    }
    everything = {e.id for e in SyntheticConnector(anchor_time=ANCHOR).collect()}
    assert subset < everything


def test_split_outcomes_agree_with_the_full_corpus():
    """The same (subject, factor) pair must score the same either way."""
    full = {(o.subject_id, o.factor_type): o.kind for o in evaluate(ANCHOR).outcomes}
    for split in SPLITS:
        for o in evaluate(ANCHOR, split=split).outcomes:
            assert full[(o.subject_id, o.factor_type)] == o.kind, (
                o.subject_id,
                o.factor_type,
            )


def test_label_counts_add_up():
    full = evaluate(ANCHOR)
    train = evaluate(ANCHOR, split=TRAIN)
    holdout = evaluate(ANCHOR, split=HOLDOUT)
    for field in (
        "true_positives",
        "false_positives",
        "false_negatives",
        "true_negatives",
    ):
        assert getattr(full, field) == getattr(train, field) + getattr(holdout, field)


def test_metrics_carry_their_split_label():
    assert evaluate(ANCHOR, split=TRAIN).split == TRAIN
    assert evaluate(ANCHOR, split=HOLDOUT).split == HOLDOUT
    assert evaluate(ANCHOR).split == "all"


# --- The reported gap ------------------------------------------------------


def test_comparison_report_renders_both_columns():
    report = compare_splits(ANCHOR)
    assert "train" in report and "holdout" in report and "gap" in report


def test_holdout_does_not_collapse():
    """
    A large negative gap means the rules memorised the training scenarios.

    Deliberately loose: this is a smoke alarm for overfitting, not a quality
    floor. Quality floors live in test_engine.py and are measured on train.
    """
    holdout = evaluate(ANCHOR, split=HOLDOUT)
    train = evaluate(ANCHOR, split=TRAIN)
    assert holdout.recall >= train.recall - 0.25, (
        f"holdout recall {holdout.recall:.1%} vs train {train.recall:.1%}: "
        "rules may be fitted to the training scenarios"
    )


def test_no_negative_control_fires_in_either_split():
    for split in SPLITS:
        m = evaluate(ANCHOR, split=split)
        assert m.false_alarms() == (), (split, m.false_alarms())
