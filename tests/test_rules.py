"""
The rule contract, tested without any real rules.

These assertions are about the shape a detection must have, not about whether
any particular detection is correct. The point of testing the contract first is
that `should_fire=False` scenarios need "declined to fire" to be a representable
outcome before a single rule body exists.
"""

from datetime import datetime, timezone

import pytest

from app.connectors.synthetic import SyntheticConnector
from app.evidence.models import RecordKind
from app.normalize.normalizer import Normalizer
from app.risk.coverage import CoverageAnalyzer
from app.risk.features import FeatureExtractor
from app.risk.models import RiskFactorAssessment, RiskFactorType, RiskSubject, RiskSubjectType
from app.risk.rules import Rule, RuleContext, RuleOutcome, assess, assess_all

ANCHOR = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)
SUBJECT = RiskSubject(subject_type=RiskSubjectType.IDENTITY, subject_id="alice")


def context_for(identity_id: str = "alice") -> RuleContext:
    estate = Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    identity = estate.identity(identity_id)
    return RuleContext(
        identity=identity,
        features=FeatureExtractor.extract_features(
            identity, estate.resources, estate.events, ANCHOR
        ),
        coverage=CoverageAnalyzer.summarize(identity, estate.events, estate, ANCHOR),
        evaluation_time=ANCHOR,
        resources=estate.resources,
        index=estate,
    )


def fired(**overrides) -> RuleOutcome:
    kwargs = dict(
        fired=True,
        subject=SUBJECT,
        impact=8.0,
        likelihood=9.0,
        confidence=0.9,
        description="Standing admin on a CRITICAL resource, never exercised.",
        recommendation="Convert to JIT-eligible with a 4h TTL.",
        evidence_ids=("ev_abc",),
    )
    kwargs.update(overrides)
    return RuleOutcome(**kwargs)


# --- RuleContext -----------------------------------------------------------


def test_context_builds_from_the_real_pipeline():
    ctx = context_for("alice")
    assert ctx.identity.id == "alice"
    assert ctx.coverage.identity_id == "alice"
    assert ctx.features.standing_critical_permission_count == 1


def test_context_rejects_mismatched_coverage():
    """A coverage summary for the wrong identity is a wiring bug, not a finding."""
    estate = Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    alice = estate.identity("alice")
    carol_coverage = CoverageAnalyzer.summarize(
        estate.identity("carol"), estate.events, estate, ANCHOR
    )
    with pytest.raises(ValueError):
        RuleContext(
            identity=alice,
            features=FeatureExtractor.extract_features(
                alice, estate.resources, estate.events, ANCHOR
            ),
            coverage=carol_coverage,
            evaluation_time=ANCHOR,
        )


def test_context_rejects_naive_evaluation_time():
    ctx = context_for()
    with pytest.raises(ValueError):
        RuleContext(
            identity=ctx.identity,
            features=ctx.features,
            coverage=ctx.coverage,
            evaluation_time=datetime(2026, 9, 9),
        )


def test_unknown_resource_degrades_silently():
    assert context_for().resource("no_such_resource") is None


def test_cite_returns_real_evidence_ids():
    ids = context_for().cite(RecordKind.PERMISSION_GRANT, "g_alice_admin")
    assert ids and all(isinstance(i, str) for i in ids)


def test_cite_without_an_index_returns_empty():
    ctx = context_for()
    bare = RuleContext(
        identity=ctx.identity,
        features=ctx.features,
        coverage=ctx.coverage,
        evaluation_time=ANCHOR,
    )
    assert bare.cite(RecordKind.PERMISSION_GRANT, "g_alice_admin") == ()


# --- RuleOutcome validation ------------------------------------------------


def test_fired_outcome_validates():
    outcome = fired()
    assert outcome.fired is True
    assert outcome.confidence == 0.9


def test_non_finding_is_representable():
    """'Ran and declined' must be a first-class result, not None."""
    outcome = RuleOutcome.no_finding()
    assert outcome.fired is False
    assert outcome.subject is None
    assert outcome.evidence_ids == ()


def test_non_finding_carrying_scores_is_rejected():
    """fired=False with impact=9.0 leaves a reader guessing which field wins."""
    with pytest.raises(ValueError):
        RuleOutcome(fired=False, impact=9.0)
    with pytest.raises(ValueError):
        RuleOutcome(fired=False, description="something happened")
    with pytest.raises(ValueError):
        RuleOutcome(fired=False, evidence_ids=("ev_abc",))
    with pytest.raises(ValueError):
        RuleOutcome(fired=False, subject=SUBJECT)


def test_fired_outcome_requires_a_subject():
    with pytest.raises(TypeError):
        fired(subject=None)


def test_fired_outcome_requires_an_explanation():
    with pytest.raises(ValueError):
        fired(description="")
    with pytest.raises(ValueError):
        fired(recommendation="   ")


def test_score_ranges_are_enforced():
    with pytest.raises(ValueError):
        fired(impact=11.0)
    with pytest.raises(ValueError):
        fired(likelihood=-1.0)
    with pytest.raises(ValueError):
        fired(confidence=1.5)


def test_bool_is_rejected_where_a_score_is_expected():
    with pytest.raises(TypeError):
        fired(impact=True)


def test_nan_confidence_is_rejected():
    with pytest.raises(ValueError):
        fired(confidence=float("nan"))


def test_evidence_ids_must_be_a_tuple():
    with pytest.raises(TypeError):
        fired(evidence_ids=["ev_abc"])


def test_outcome_is_hashable():
    assert hash(fired()) is not None


# --- Promotion to the output DTO -------------------------------------------


def test_promotion_produces_a_valid_assessment():
    assessment = fired().to_assessment("stale_standing_access.v1", RiskFactorType.STALE_ACCESS)
    assert isinstance(assessment, RiskFactorAssessment)
    assert assessment.factor_type is RiskFactorType.STALE_ACCESS
    assert assessment.confidence == 0.9
    assert assessment.evidence_ids == ("ev_abc",)


def test_assessment_id_is_deterministic_not_random():
    """Two runs over identical evidence must produce diffable assessments."""
    a = fired().to_assessment("stale_standing_access.v1", RiskFactorType.STALE_ACCESS)
    b = fired().to_assessment("stale_standing_access.v1", RiskFactorType.STALE_ACCESS)
    assert a.id == b.id
    assert a == b


def test_assessment_id_separates_subjects():
    other = RiskSubject(subject_type=RiskSubjectType.ACCESS_GRANT, subject_id="g_alice_admin")
    a = fired().to_assessment("r.v1", RiskFactorType.STALE_ACCESS)
    b = fired(subject=other).to_assessment("r.v1", RiskFactorType.STALE_ACCESS)
    assert a.id != b.id


def test_promoting_a_non_finding_raises():
    with pytest.raises(ValueError):
        RuleOutcome.no_finding().to_assessment("r.v1", RiskFactorType.STALE_ACCESS)


# --- The Rule protocol -----------------------------------------------------


class AlwaysFires:
    rule_id = "always.v1"
    factor_type = RiskFactorType.EXCESSIVE_PRIVILEGE

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        return fired()


class NeverFires:
    rule_id = "never.v1"
    factor_type = RiskFactorType.STALE_ACCESS

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        return RuleOutcome.no_finding()


class ReturnsGarbage:
    rule_id = "garbage.v1"
    factor_type = RiskFactorType.STALE_ACCESS

    def evaluate(self, ctx: RuleContext):
        return "high risk"


def test_rules_satisfy_the_protocol_structurally():
    """No rule inherits from anything; the protocol is satisfied by shape."""
    assert isinstance(AlwaysFires(), Rule)
    assert isinstance(NeverFires(), Rule)


def test_assess_returns_none_when_a_rule_declines():
    assert assess(NeverFires(), context_for()) is None


def test_assess_promotes_a_fired_rule():
    result = assess(AlwaysFires(), context_for())
    assert result is not None
    assert result.factor_type is RiskFactorType.EXCESSIVE_PRIVILEGE
    assert result.id.startswith("always.v1:")


def test_assess_rejects_a_rule_returning_the_wrong_type():
    with pytest.raises(TypeError):
        assess(ReturnsGarbage(), context_for())


def test_assess_all_keeps_only_findings_and_preserves_order():
    ctx = context_for()
    results = assess_all([NeverFires(), AlwaysFires(), NeverFires()], ctx)
    assert len(results) == 1
    assert results[0].id.startswith("always.v1:")


def test_assess_all_with_no_rules_is_empty_not_an_error():
    assert assess_all([], context_for()) == ()
