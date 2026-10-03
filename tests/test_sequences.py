"""
The cross-rule sequence stage: one identity's reported, event-citing findings
from distinct rules, with evidence of their own, close together in time.
"""

from datetime import datetime, timedelta, timezone

from app.risk.models import RiskFactorAssessment, RiskFactorType, RiskSubject, RiskSubjectType
from app.risk.sequences import correlate

T0 = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)
SUBJECT = RiskSubject(subject_type=RiskSubjectType.IDENTITY, subject_id="a")


def finding(rule, evidence, impact=6.0, likelihood=7.0, confidence=0.9):
    return (rule, RiskFactorAssessment(
        id=f"{rule}:identity:a", factor_type=RiskFactorType.ANOMALOUS_BEHAVIOR, subject=SUBJECT,
        impact=impact, likelihood=likelihood, confidence=confidence,
        evidence_ids=tuple(evidence), description="d", recommendation="r",
    ))


def times(**offsets_hours):
    return {eid: T0 + timedelta(hours=h) for eid, h in offsets_hours.items()}


def test_two_rules_close_together_are_one_sequence():
    out = correlate([finding("burst", ["e1"]), finding("pull", ["e2"], impact=8.5)],
                    times(e1=0, e2=2))
    assert out is not None
    assert out.description.startswith("2 detections form one sequence within 2.0 hours: burst")
    assert out.impact == 8.5 and out.likelihood == 8.0  # worst impact; likeliest + 1
    assert out.evidence_ids == ("e1", "e2")


def test_far_apart_findings_are_not_a_sequence():
    assert correlate([finding("burst", ["e1"]), finding("pull", ["e2"])], times(e1=0, e2=48)) is None


def test_a_stage_needs_evidence_of_its_own():
    """A rule that cites a subset of another's events is the same stage seen twice."""
    staged = [finding("burst", ["e1"]), finding("escalation", ["e1", "e2"])]
    assert correlate(staged, times(e1=0, e2=0.5)) is None


def test_findings_without_events_have_no_place_in_a_timeline():
    """Staleness and privilege findings cite grants, not moments."""
    assert correlate([finding("burst", ["e1"]), finding("stale", ["g1"])], times(e1=0)) is None


def test_a_chain_is_as_trusted_as_its_weakest_stage():
    staged = [finding("a", ["e1"], confidence=0.9), finding("b", ["e2"], confidence=0.5),
              finding("c", ["e3"], confidence=0.8)]
    out = correlate(staged, times(e1=0, e2=10, e3=20))
    assert out.confidence == 0.5
    assert out.description.startswith("3 detections")  # chained: each within 24h of the last


def test_correlation_is_deterministic_regardless_of_input_order():
    staged = [finding("pull", ["e2"]), finding("burst", ["e1"])]
    t = times(e1=0, e2=2)
    assert correlate(staged, t) == correlate(list(reversed(staged)), t)
