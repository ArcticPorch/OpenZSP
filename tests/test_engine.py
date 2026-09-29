"""
Scoring, engine orchestration, and the detection metric itself.

The metric tests carry floors rather than exact values. A floor fails when
calibration regresses and passes when it improves, which is the behaviour you
want from a number that is supposed to move.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.connectors.synthetic import FRESH, HOLDOUT, SCENARIOS, TRAIN, SyntheticConnector
from app.normalize.normalizer import Normalizer
from app.risk import scoring
from app.risk.coverage import CoverageAnalyzer
from app.risk.detections import ALL_RULES
from app.risk.engine import RiskEngine
from app.risk.evaluation import evaluate, format_report
from app.risk.models import RiskFactorType, RiskLevel, RiskSubject, RiskSubjectType
from app.risk.rules import Rule, RuleOutcome

ANCHOR = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)

# Calibration floors. Raise them when you genuinely improve detection; never
# lower one to make a change pass.
MIN_RECALL = 0.85
MIN_PRECISION = 0.90
MIN_SPECIFICITY = 1.00


def estate():
    return Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())


def results():
    return {r.identity_id: r for r in RiskEngine().assess_estate(estate(), ANCHOR)}


# --- Scoring primitives ----------------------------------------------------


def test_freshness_decays_by_half_life():
    assert scoring.freshness_factor(0.0) == 1.0
    assert scoring.freshness_factor(7.0) == pytest.approx(0.5)
    assert scoring.freshness_factor(14.0) == pytest.approx(0.25)


def test_no_activity_evidence_is_maximum_uncertainty_not_freshness():
    assert scoring.freshness_factor(None) == 0.0


def test_confidence_is_a_product_not_a_mean():
    """One fatal factor must not be rescued by three good ones."""
    est = estate()
    carol = CoverageAnalyzer.summarize(
        est.identity("carol"), est.events, est, ANCHOR
    )
    conf = scoring.confidence_from_coverage(carol)
    # completeness .4 * reliability .95 * freshness .25 -> well under a mean.
    assert conf < 0.15
    mean_like = (
        carol.min_completeness
        + carol.min_source_reliability
        + carol.min_identity_mapping_confidence
    ) / 3
    assert conf < mean_like


def test_aggregation_compounds_without_saturating():
    """Two medium findings should exceed either alone and stay under 100."""

    def factor(impact, likelihood, confidence, suffix):
        return RuleOutcome(
            fired=True,
            subject=RiskSubject(
                subject_type=RiskSubjectType.IDENTITY, subject_id=f"x{suffix}"
            ),
            impact=impact,
            likelihood=likelihood,
            confidence=confidence,
            description="d",
            recommendation="r",
        ).to_assessment(f"r{suffix}.v1", RiskFactorType.STALE_ACCESS)

    one = factor(7.0, 7.0, 1.0, 1)
    two = factor(7.0, 7.0, 1.0, 2)
    single = scoring.aggregate_risk([one])
    both = scoring.aggregate_risk([one, two])
    assert both > single
    assert both < 100.0


def test_confidence_discounts_contribution_not_impact():
    """An uncertain finding scores lower without its impact being rewritten."""
    outcome = RuleOutcome(
        fired=True,
        subject=RiskSubject(subject_type=RiskSubjectType.IDENTITY, subject_id="x"),
        impact=9.0,
        likelihood=9.0,
        confidence=0.2,
        description="d",
        recommendation="r",
    )
    a = outcome.to_assessment("r.v1", RiskFactorType.STALE_ACCESS)
    assert a.impact == 9.0  # unchanged
    assert scoring.weighted_risk(a) < scoring.factor_risk(9.0, 9.0)


def test_risk_level_bands():
    assert scoring.risk_level(95.0) is RiskLevel.CRITICAL
    assert scoring.risk_level(60.0) is RiskLevel.HIGH
    assert scoring.risk_level(30.0) is RiskLevel.MEDIUM
    assert scoring.risk_level(5.0) is RiskLevel.LOW


# --- Engine ----------------------------------------------------------------


def test_every_rule_satisfies_the_protocol():
    for rule in ALL_RULES:
        assert isinstance(rule, Rule), rule


def test_rule_ids_are_unique_and_versioned():
    ids = [r.rule_id for r in ALL_RULES]
    assert len(ids) == len(set(ids))
    assert all("." in i and i.split(".")[-1].startswith("v") for i in ids), ids


def test_engine_produces_valid_assessments_for_every_identity():
    for result in RiskEngine().assess_estate(estate(), ANCHOR):
        a = result.assessment
        assert 0.0 <= a.overall_score <= 100.0
        assert 0.0 <= a.global_confidence <= 1.0
        assert a.evaluated_at == ANCHOR
        assert result.rule_errors == (), result.rule_errors


def test_a_raising_rule_does_not_sink_the_run():
    """One bad rule must not cost every finding from the rules after it."""

    class Exploding:
        rule_id = "boom.v1"
        factor_type = RiskFactorType.STALE_ACCESS

        def evaluate(self, ctx):
            raise RuntimeError("kaboom")

    est = estate()
    engine = RiskEngine(rules=(Exploding(),) + ALL_RULES)
    alice = est.identity("alice")
    result = engine.assess_identity(
        alice, est.resources, est.events, est, ANCHOR
    )
    assert result.rule_errors and result.rule_errors[0][0] == "boom.v1"
    assert result.assessment.triggered_factors, "later rules must still run"


def test_findings_are_deduped_per_factor_and_subject():
    """Two staleness rules on one identity are one problem, not two risks."""
    for result in RiskEngine().assess_estate(estate(), ANCHOR):
        seen = [(f.factor_type, f.subject) for f in result.assessment.triggered_factors]
        assert len(seen) == len(set(seen)), result.identity_id


def test_assessments_are_reproducible():
    a = RiskEngine().assess_estate(estate(), ANCHOR)
    b = RiskEngine().assess_estate(estate(), ANCHOR)
    assert [r.assessment for r in a] == [r.assessment for r in b]


def test_future_evaluation_time_does_not_leak_events():
    """Everything is relative to evaluation_time, never wall clock."""
    est = estate()
    early = ANCHOR - timedelta(days=365)
    result = RiskEngine().assess_identity(
        est.identity("svc_deploy"), est.resources, est.events, est, early
    )
    factors = {f.factor_type for f in result.assessment.triggered_factors}
    assert RiskFactorType.ANOMALOUS_BEHAVIOR not in factors


# --- Blind spots are suppressed, not cleared -------------------------------


def test_blind_spot_findings_are_suppressed_not_silently_dropped():
    """
    carol's rules genuinely fire; the engine holds them back on trust grounds.

    This is the assertion that proves the confidence architecture earns its
    keep. If `suppressed` were empty, the negative control would be passing by
    coincidence rather than by design.
    """
    carol = results()["carol"]
    assert carol.assessment.triggered_factors == ()
    assert carol.suppressed, "nothing fired at all -- the control proves nothing"
    assert all(f.confidence < scoring.MIN_REPORTING_CONFIDENCE for f in carol.suppressed)


def test_incomplete_collection_is_suppressed_too():
    """priya's collection is current; only completeness and mapping are degraded."""
    priya = results()["priya"]
    assert priya.assessment.triggered_factors == ()
    assert priya.suppressed


def test_a_blind_identity_does_not_report_a_confident_all_clear():
    carol = results()["carol"]
    assert carol.assessment.overall_score == 0.0
    # ...but the report says we are not sure, rather than implying safety.
    assert carol.assessment.global_confidence < scoring.MIN_REPORTING_CONFIDENCE


def test_a_healthy_identity_reports_high_confidence():
    alice = results()["alice"]
    assert alice.assessment.triggered_factors
    assert alice.assessment.global_confidence > 0.9


# --- Detection quality -----------------------------------------------------


def test_detection_meets_calibration_floors():
    """
    Floors are measured on TRAIN, which is where calibration is allowed to look.

    Holding a floor against the holdout would convert it into training data the
    first time someone edited a threshold to make this test pass.
    """
    m = evaluate(ANCHOR, split=TRAIN)
    assert m.recall >= MIN_RECALL, format_report(m)
    assert m.precision >= MIN_PRECISION, format_report(m)
    assert m.specificity >= MIN_SPECIFICITY, format_report(m)


def test_no_negative_control_fires_in_train():
    """
    The controls are the only firings we can be certain would be wrong.

    Asserted on TRAIN only, where tuning happens. Held-out false alarms are a
    *measurement*, pinned exactly below -- a test demanding zero there would
    pressure the next person to tune against a held-out split until it passed.
    """
    m = evaluate(ANCHOR, split=TRAIN)
    assert m.false_alarms() == (), [(o.subject_id, o.factor_type) for o in m.false_alarms()]


def _alarms(split):
    return {(o.subject_id, o.factor_type) for o in evaluate(ANCHOR, split=split).false_alarms()}


def test_fresh_false_alarms_are_exactly_the_recorded_ones():
    """
    The one FRESH v2 reading (2026-09-29, after calibration cycle 2), pinned.

    A newly connected integration's initial backfill reads as a bulk read
    because it has no history (the rule fires on a zero baseline by design),
    and a Treasury analyst on the AP ledger reads as a context mismatch
    because departments are flat strings with no notion of adjacent teams.
    If this set shrinks, check the change was made against TRAIN.
    """
    assert _alarms(FRESH) == {
        ("svc_helpdesk_sync", "ANOMALOUS_BEHAVIOR"),
        ("treasury_analyst", "CONTEXT_MISMATCH"),
    }


def test_holdout_false_alarms_are_exactly_the_recorded_ones():
    """
    HOLDOUT now includes the retired FRESH v1. Its break-glass account carries
    no tag in its evidence, so the engine cannot know it is one -- the fix was
    the tag, and the tag has to come from the source of record.
    """
    assert _alarms(HOLDOUT) == {("breakglass_root", "STALE_ACCESS")}


def test_break_glass_tag_excuses_dormancy_never_privilege():
    r = results()["breakglass_payments"]
    kinds = {f.factor_type for f in r.assessment.triggered_factors}
    assert RiskFactorType.EXCESSIVE_PRIVILEGE in kinds
    assert RiskFactorType.STALE_ACCESS not in kinds
    assert estate().identity("breakglass_payments").is_break_glass is True


def test_unlabelled_firings_are_reported_not_hidden():
    """
    Precision is an upper bound while unlabelled firings exist.

    This test does not demand zero; it demands that the number is surfaced, so
    the bound stays visible instead of being quietly assumed away.
    """
    m = evaluate(ANCHOR)
    report = format_report(m)
    if m.unlabelled_firings:
        assert "UNLABELLED FIRINGS" in report
        assert "upper bound" in report


def test_known_misses_are_exactly_the_documented_ones():
    """
    Every labelled positive fires, in every split. If one stops, the change
    was a regression worth catching.

    History, because an empty set hides it: oscar/CONTEXT_MISMATCH was fixed by
    `peer_access_outlier.v1` and agent_ops/EXCESSIVE_PRIVILEGE by
    `privilege_creep.v1` (both 2026-09-29, tuned on TRAIN). frank's was removed
    as a label on review, not fixed -- it double-counted his departure.
    """
    m = evaluate(ANCHOR)
    assert {(o.subject_id, o.factor_type) for o in m.misses()} == set()


def test_metrics_are_deterministic():
    assert evaluate(ANCHOR).precision == evaluate(ANCHOR).precision
    assert evaluate(ANCHOR).recall == evaluate(ANCHOR).recall


def test_report_renders():
    assert "precision" in format_report(evaluate(ANCHOR))


def test_every_scenario_contributes_at_least_one_outcome():
    """A scenario nobody scores is dead weight in the corpus."""
    m = evaluate(ANCHOR)
    scored = {o.subject_id for o in m.outcomes}
    for scenario in SCENARIOS:
        subjects = {f.subject_id for f in scenario.expected}
        assert subjects & scored, scenario.name
