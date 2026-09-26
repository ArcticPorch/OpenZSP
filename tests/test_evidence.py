from datetime import datetime, timedelta, timezone

import pytest

from app.evidence.connector import EvidenceConnector
from app.evidence.models import (
    Evidence,
    EvidenceQuality,
    RecordKind,
    SourceRef,
    SourceType,
    canonical_payload,
    content_id,
)


PERFECT = EvidenceQuality(
    source_reliability=1.0,
    integrity_authenticity=1.0,
    identity_mapping_confidence=1.0,
    completeness=1.0,
)

SRC = SourceRef(source_type=SourceType.AWS_CLOUDTRAIL, source_id="123456789012/us-east-1")

T0 = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


def make_evidence(**overrides) -> Evidence:
    kwargs = dict(
        id="ev_1",
        source=SRC,
        record_kind=RecordKind.ACTIVITY_EVENT,
        observed_at=T0,
        collected_at=T0 + timedelta(minutes=5),
        quality=PERFECT,
        entity_references=(("identity_id", "alice"),),
        payload=(("action", "s3:DeleteObject"),),
    )
    kwargs.update(overrides)
    return Evidence(**kwargs)


# --- SourceRef ---


def test_source_ref_validation():
    assert str(SRC) == "aws_cloudtrail:123456789012/us-east-1"

    with pytest.raises(TypeError):
        SourceRef(source_type="cloudtrail", source_id="x")  # type: ignore

    with pytest.raises(ValueError):
        SourceRef(source_type=SourceType.SYNTHETIC, source_id="  ")


# --- EvidenceQuality ---


def test_evidence_quality_validation():
    assert PERFECT.source_reliability == 1.0

    # bool rejected as a number
    with pytest.raises(TypeError):
        EvidenceQuality(
            source_reliability=True,  # type: ignore
            integrity_authenticity=0.9,
            identity_mapping_confidence=1.0,
            completeness=0.5,
        )

    for bad in (float("nan"), float("inf"), 1.1, -0.1):
        with pytest.raises(ValueError):
            EvidenceQuality(
                source_reliability=bad,
                integrity_authenticity=0.9,
                identity_mapping_confidence=1.0,
                completeness=0.5,
            )


def test_evidence_quality_has_no_frozen_freshness():
    """Freshness is derived at evaluation time, never stored on the record."""
    assert not hasattr(PERFECT, "freshness_score")


# --- Evidence ---


def test_evidence_requires_tz_aware_timestamps():
    with pytest.raises(ValueError):
        make_evidence(observed_at=datetime(2026, 9, 1, 12, 0, 0))  # naive

    with pytest.raises(ValueError):
        make_evidence(collected_at=datetime(2026, 9, 1, 12, 0, 0))  # naive


def test_evidence_structural_validation():
    ev = make_evidence()
    assert ev.id == "ev_1"

    with pytest.raises(TypeError):
        make_evidence(entity_references=[("identity_id", "alice")])  # list not tuple

    with pytest.raises(TypeError):
        make_evidence(entity_references=(("identity_id", "alice", "extra"),))

    with pytest.raises(TypeError):
        make_evidence(source="aws_cloudtrail")  # not a SourceRef

    with pytest.raises(ValueError):
        make_evidence(payload=(("", "value"),))  # empty payload key

    with pytest.raises(TypeError):
        make_evidence(record_kind="activity_event")  # not a RecordKind


def test_bitemporal_derived_facts():
    ev = make_evidence(observed_at=T0, collected_at=T0 + timedelta(hours=2))
    evaluation_time = T0 + timedelta(days=1)

    # Age is measured from when the fact was true...
    assert ev.age_at(evaluation_time) == timedelta(days=1)
    # ...staleness from when we learned it. They are not the same number.
    assert ev.staleness_at(evaluation_time) == timedelta(hours=22)
    assert ev.collection_lag == timedelta(hours=2)


def test_negative_collection_lag_is_allowed():
    """Clock skew is real; rejecting these records would drop valid data."""
    ev = make_evidence(observed_at=T0, collected_at=T0 - timedelta(seconds=30))
    assert ev.collection_lag == timedelta(seconds=-30)


def test_derived_facts_reject_naive_evaluation_time():
    ev = make_evidence()
    with pytest.raises(ValueError):
        ev.age_at(datetime(2026, 9, 2, 12, 0, 0))


def test_evidence_is_immutable_and_hashable():
    ev = make_evidence()
    with pytest.raises(AttributeError):
        ev.id = "ev_2"  # type: ignore
    assert hash(ev) == hash(make_evidence())


def test_payload_and_reference_accessors():
    ev = make_evidence()
    assert ev.payload_dict() == {"action": "s3:DeleteObject"}
    assert ev.references_dict() == {"identity_id": "alice"}


# --- Content addressing ---


def test_canonical_payload_is_order_independent():
    a = canonical_payload((("b", 2), ("a", 1)))
    b = canonical_payload((("a", 1), ("b", 2)))
    assert a == b


def test_content_id_is_deterministic_and_ignores_collection_time():
    args = (
        SRC,
        RecordKind.ACTIVITY_EVENT,
        T0,
        (("identity_id", "alice"),),
        (("action", "s3:DeleteObject"),),
    )
    first = content_id(*args)
    second = content_id(*args)

    # Re-ingesting the same fact yields the same id, so dedup is free.
    assert first == second
    assert first.startswith("ev_")

    # A different observation must not collide.
    assert content_id(SRC, RecordKind.ACTIVITY_EVENT, T0, (("identity_id", "bob"),), args[4]) != first
    assert (
        content_id(SRC, RecordKind.ACTIVITY_EVENT, T0 + timedelta(seconds=1), args[3], args[4])
        != first
    )

    # The record kind is part of the identity of an observation.
    assert content_id(SRC, RecordKind.IDENTITY, T0, args[3], args[4]) != first


def test_content_id_survives_reordered_inputs():
    """Insertion order is not part of the fact, so it must not change the id."""
    refs_a = (("identity_id", "alice"), ("resource_id", "bucket"))
    refs_b = (("resource_id", "bucket"), ("identity_id", "alice"))
    payload = (("action", "read"),)
    k = RecordKind.PERMISSION_GRANT
    assert content_id(SRC, k, T0, refs_a, payload) == content_id(SRC, k, T0, refs_b, payload)


# --- Connector protocol ---


def test_connector_protocol_is_structural():
    class Stub:
        def source_ref(self) -> SourceRef:
            return SRC

        def collect(self, *, since=None, until=None):
            yield make_evidence()

    # Satisfied by shape alone -- no subclassing, no framework import.
    assert isinstance(Stub(), EvidenceConnector)
    assert not isinstance(object(), EvidenceConnector)

    collected = list(Stub().collect())
    assert len(collected) == 1
    assert collected[0].source == SRC
