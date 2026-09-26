from datetime import datetime, timedelta, timezone

import pytest

from app.connectors.synthetic import SCENARIOS, ExpectedFinding, SyntheticConnector
from app.evidence.connector import EvidenceConnector
from app.evidence.models import RecordKind, SourceType
from app.risk.models import RiskFactorType


ANCHOR = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)


def make_connector(**kwargs) -> SyntheticConnector:
    return SyntheticConnector(anchor_time=ANCHOR, **kwargs)


# --- Contract ---


def test_satisfies_connector_protocol():
    assert isinstance(make_connector(), EvidenceConnector)


def test_source_ref():
    ref = make_connector().source_ref()
    assert ref.source_type is SourceType.SYNTHETIC


def test_rejects_naive_anchor_time():
    with pytest.raises(ValueError):
        SyntheticConnector(anchor_time=datetime(2026, 9, 9))


def test_collect_streams_rather_than_materializes():
    import types

    assert isinstance(make_connector().collect(), types.GeneratorType)


# --- Determinism ---


def test_output_is_deterministic():
    a = [e.id for e in make_connector(filler_identities=5).collect()]
    b = [e.id for e in make_connector(filler_identities=5).collect()]
    assert a == b
    assert len(a) > 0


def test_seed_changes_filler_but_not_scenarios():
    def ids(seed):
        return [e.id for e in make_connector(seed=seed, filler_identities=5).collect()]

    scenario_only = {e.id for e in make_connector(seed=0).collect()}
    a, b = ids(0), ids(1)

    assert a != b, "filler should vary with the seed"
    # Scenario records are the labelled ones; they must be stable regardless.
    assert scenario_only.issubset(set(a))
    assert scenario_only.issubset(set(b))


def test_no_wall_clock_dependency():
    """Everything is anchored, so a different anchor shifts every observation."""
    early = {e.id for e in make_connector().collect()}
    later = {
        e.id
        for e in SyntheticConnector(anchor_time=ANCHOR + timedelta(days=1)).collect()
    }
    assert early.isdisjoint(later)


def test_scenarios_are_independent():
    """Adding or reordering one scenario must not perturb another's data."""
    subset = [s for s in SCENARIOS if s.name == "dormant_standing_admin"]
    alone = {e.id for e in make_connector(scenarios=subset).collect()}
    together = {e.id for e in make_connector().collect()}
    assert alone.issubset(together)


# --- Evidence shape ---


def test_all_records_are_well_formed():
    for ev in make_connector(filler_identities=3).collect():
        assert ev.observed_at.tzinfo is not None
        assert ev.collected_at.tzinfo is not None
        assert ev.id.startswith("ev_")
        assert ev.source.source_type is SourceType.SYNTHETIC
        assert isinstance(ev.record_kind, RecordKind)
        assert ev.entity_references, "every record must be attributable to an entity"


def test_ids_are_unique():
    ids = [e.id for e in make_connector(filler_identities=10).collect()]
    assert len(ids) == len(set(ids))


def test_every_scenario_emits_all_needed_kinds():
    for scenario in SCENARIOS:
        kinds = {
            e.record_kind for e in make_connector(scenarios=[scenario]).collect()
        }
        assert RecordKind.IDENTITY in kinds, scenario.name
        assert RecordKind.PERMISSION_GRANT in kinds, scenario.name


def test_grants_reference_a_declared_resource():
    """No dangling resource_id: a grant must point at a resource we also emitted."""
    records = list(make_connector().collect())
    declared = {
        e.references_dict()["resource_id"]
        for e in records
        if e.record_kind is RecordKind.RESOURCE
    }
    for ev in records:
        if ev.record_kind in (RecordKind.PERMISSION_GRANT, RecordKind.ACTIVITY_EVENT):
            assert ev.references_dict()["resource_id"] in declared, ev.id


# --- Ground truth ---


def test_expected_findings_use_real_factor_types():
    """
    Recovers the safety of the enum without making the ingestion layer import it.
    """
    valid = {f.value for f in RiskFactorType}
    for finding in make_connector().expected_findings():
        assert finding.factor_type in valid, finding.factor_type


def test_ground_truth_includes_negative_controls():
    findings = make_connector().expected_findings()
    assert any(f.should_fire for f in findings)
    assert any(not f.should_fire for f in findings), (
        "a rule that fires on everything must be detectable as wrong"
    )


def test_expected_finding_validation():
    with pytest.raises(ValueError):
        ExpectedFinding("", "alice", "why")
    with pytest.raises(ValueError):
        ExpectedFinding("STALE_ACCESS", "  ", "why")


# --- Scenario semantics worth pinning down ---


def test_dormant_admin_is_active_but_grant_is_not():
    """
    The whole point of the scenario: identity-level activity looks healthy while
    the privileged grant is untouched. A per-identity last-use timestamp misses it.
    """
    records = list(make_connector(scenarios=[SCENARIOS[0]]).collect())
    events = [e for e in records if e.record_kind is RecordKind.ACTIVITY_EVENT]
    assert events, "alice must look active"

    admin_res = "prod_payments_db"
    assert all(e.references_dict()["resource_id"] != admin_res for e in events)


def test_blind_spot_scenario_has_lagging_collection():
    scenario = next(s for s in SCENARIOS if s.name == "stale_connector_blind_spot")
    records = list(make_connector(scenarios=[scenario]).collect())
    lagging = [e for e in records if e.staleness_at(ANCHOR) > timedelta(days=7)]
    assert lagging, "the blind-spot scenario must contain stale collections"
    assert any(e.quality.completeness < 1.0 for e in lagging)


def test_window_filtering_is_applied():
    since = ANCHOR - timedelta(days=2)
    records = list(make_connector(filler_identities=5).collect(since=since))
    assert records
    assert all(e.observed_at >= since for e in records)

    until = ANCHOR - timedelta(days=100)
    assert all(e.observed_at <= until for e in make_connector().collect(until=until))


def test_window_rejects_naive_bounds():
    with pytest.raises(ValueError):
        list(make_connector().collect(since=datetime(2026, 9, 1)))
