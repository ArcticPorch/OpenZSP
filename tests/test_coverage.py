"""
Coverage measures what we know, not how risky an identity is.

The load-bearing test here is `test_blind_spot_is_visible_in_coverage_only`:
alice and carol both present as inactive at the feature layer, and the only
thing that separates a genuinely dormant grant from a connector that stopped
reporting lives in the evidence. If that assertion ever fails, no scoring
architecture built on top can pass the `stale_connector_blind_spot` control.
"""

from datetime import datetime, timezone

import pytest

from app.connectors.synthetic import SyntheticConnector
from app.normalize.normalizer import Estate, Normalizer
from app.risk.coverage import CoverageAnalyzer, CoverageSummary, EvidenceIndex
from app.risk.features import FeatureExtractor

ANCHOR = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)


def build_estate() -> Estate:
    return Normalizer().normalize(
        SyntheticConnector(anchor_time=ANCHOR).collect()
    )


def summarize(estate: Estate, identity_id: str) -> CoverageSummary:
    identity = estate.identity(identity_id)
    assert identity is not None, identity_id
    return CoverageAnalyzer.summarize(identity, estate.events, estate, ANCHOR)


# --- Structural contract ---------------------------------------------------


def test_estate_satisfies_evidence_index_structurally():
    """Estate was never told about EvidenceIndex; it should still satisfy it."""
    assert isinstance(build_estate(), EvidenceIndex)


def test_summarize_rejects_naive_evaluation_time():
    estate = build_estate()
    alice = estate.identity("alice")
    with pytest.raises(ValueError):
        CoverageAnalyzer.summarize(
            alice, estate.events, estate, datetime(2026, 9, 9)  # naive
        )


# --- Validation ------------------------------------------------------------


def _valid_kwargs(**overrides):
    kwargs = dict(
        identity_id="alice",
        evidence_count=1,
        source_count=1,
        grant_evidence_count=0,
        event_evidence_count=0,
        min_completeness=1.0,
        min_source_reliability=1.0,
        min_identity_mapping_confidence=1.0,
        min_integrity_authenticity=1.0,
        mean_completeness=1.0,
        mean_source_reliability=1.0,
        unknown_capability_grant_count=0,
        classified_grant_count=1,
        newest_collected_at=ANCHOR,
        oldest_collected_at=ANCHOR,
        newest_observed_at=ANCHOR,
        collection_staleness_days=0.0,
        max_collection_staleness_days=0.0,
        activity_collection_staleness_days=0.0,
        observation_age_days=0.0,
        max_collection_lag_days=0.0,
    )
    kwargs.update(overrides)
    return kwargs


def test_quality_out_of_range_raises_value_error():
    with pytest.raises(ValueError):
        CoverageSummary(**_valid_kwargs(min_completeness=1.5))


def test_quality_wrong_type_raises_type_error():
    with pytest.raises(TypeError):
        CoverageSummary(**_valid_kwargs(min_completeness="1.0"))


def test_bool_rejected_where_a_number_is_expected():
    with pytest.raises(TypeError):
        CoverageSummary(**_valid_kwargs(min_completeness=True))


def test_negative_count_raises_value_error():
    with pytest.raises(ValueError):
        CoverageSummary(**_valid_kwargs(evidence_count=-1))


def test_naive_timestamp_raises_value_error():
    with pytest.raises(ValueError):
        CoverageSummary(**_valid_kwargs(newest_collected_at=datetime(2026, 9, 9)))


def test_negative_collection_lag_is_allowed():
    """Clock skew is normal; rejecting it would drop real data."""
    summary = CoverageSummary(**_valid_kwargs(max_collection_lag_days=-0.5))
    assert summary.max_collection_lag_days == -0.5


def test_summary_is_hashable():
    assert hash(CoverageSummary(**_valid_kwargs())) is not None


# --- Aggregation semantics -------------------------------------------------


def test_no_evidence_yields_zero_not_perfect_confidence():
    """
    Absence of evidence is not evidence of absence.

    An unobserved identity must read as "we know nothing", never inherit a
    default asserting perfect knowledge.
    """

    class EmptyIndex:
        def evidence_for(self, kind, entity_id):
            return ()

        def evidence_ids_for(self, kind, entity_id):
            return ()

    estate = build_estate()
    summary = CoverageAnalyzer.summarize(
        estate.identity("alice"), estate.events, EmptyIndex(), ANCHOR
    )
    assert summary.evidence_count == 0
    assert summary.has_evidence is False
    assert summary.min_completeness == 0.0
    assert summary.min_source_reliability == 0.0
    assert summary.newest_collected_at is None
    assert summary.collection_staleness_days is None
    assert summary.activity_collection_staleness_days is None


def test_quality_aggregates_by_weakest_link_not_mean():
    """One degraded source must drag the min down even when the mean looks fine."""
    carol = summarize(build_estate(), "carol")
    assert carol.min_completeness == pytest.approx(0.4)
    assert carol.min_completeness <= carol.mean_completeness


def test_coverage_counts_grants_and_events_separately():
    alice = summarize(build_estate(), "alice")
    assert alice.grant_evidence_count == 1
    assert alice.event_evidence_count == 10  # reads on the wiki, days 0..27 step 3
    # identity record + grants + events, deduplicated on id
    assert alice.evidence_count == 1 + alice.grant_evidence_count + alice.event_evidence_count


# --- The blind spot --------------------------------------------------------


def test_blind_spot_is_visible_in_coverage_only():
    """
    alice is genuinely dormant. carol only looks dormant because collection
    stopped. Features cannot tell them apart; coverage must.
    """
    estate = build_estate()

    alice_f = FeatureExtractor.extract_features(
        estate.identity("alice"), estate.resources, estate.events, ANCHOR
    )
    carol_f = FeatureExtractor.extract_features(
        estate.identity("carol"), estate.resources, estate.events, ANCHOR
    )

    # Both hold standing access, both show no privileged use at all. Nothing in
    # the feature vector says whether that silence is real or unobserved.
    assert alice_f.standing_permission_count >= 1
    assert carol_f.standing_permission_count >= 1
    assert alice_f.days_since_last_privileged_use is None
    assert carol_f.days_since_last_privileged_use is None

    alice_c = summarize(estate, "alice")
    carol_c = summarize(estate, "carol")

    # Alice: fresh, complete collection. Her quiet is real.
    assert alice_c.min_completeness == 1.0
    assert alice_c.activity_collection_staleness_days == pytest.approx(0.0, abs=0.01)

    # Carol: we stopped hearing about her activity a fortnight ago.
    assert carol_c.min_completeness == pytest.approx(0.4)
    assert carol_c.activity_collection_staleness_days == pytest.approx(14.0, abs=0.01)

    # The separation a confidence-carrying rule needs.
    assert carol_c.min_completeness < alice_c.min_completeness
    assert (
        carol_c.activity_collection_staleness_days
        > alice_c.activity_collection_staleness_days
    )


def test_observation_age_and_collection_staleness_are_different_signals():
    """
    Carol's newest *observation* is 15 days old and her newest *collection* is
    14 days old. An engine tracking one timestamp cannot tell dormancy from
    blindness; these are the two numbers that separate them.
    """
    carol = summarize(build_estate(), "carol")
    assert carol.activity_collection_staleness_days == pytest.approx(14.0, abs=0.01)

    # Her identity row kept being re-collected on every run, so the optimistic
    # "heard anything lately" reading is a clean 0.0 -- which is exactly why a
    # rule must not use it as the blind-spot signal.
    assert carol.collection_staleness_days == pytest.approx(0.0, abs=0.01)
    assert carol.max_collection_staleness_days == pytest.approx(14.0, abs=0.01)


def test_healthy_identity_has_fresh_coverage():
    """bob is the negative control: active, fully collected, nothing to excuse."""
    bob = summarize(build_estate(), "bob")
    assert bob.min_completeness == 1.0
    assert bob.activity_collection_staleness_days == pytest.approx(0.0, abs=0.01)
    assert bob.max_collection_staleness_days == pytest.approx(0.0, abs=0.01)
    assert bob.event_evidence_count == 21
