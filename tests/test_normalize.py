from datetime import datetime, timedelta, timezone

import pytest

from app.connectors.synthetic import SCENARIOS, SyntheticConnector
from app.evidence.models import (
    Evidence,
    EvidenceQuality,
    RecordKind,
    SourceRef,
    SourceType,
)
from app.models.identity import IdentityType
from app.models.capability import Capability
from app.models.permission import GrantLifecycle
from app.models.resource import Sensitivity
from app.normalize.normalizer import Estate, Normalizer

ANCHOR = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)
SRC = SourceRef(source_type=SourceType.SYNTHETIC, source_id="test")
Q = EvidenceQuality(
    source_reliability=0.9,
    integrity_authenticity=1.0,
    identity_mapping_confidence=1.0,
    completeness=1.0,
)


def ev(kind, refs, payload, *, observed_at=ANCHOR, ev_id=None, reliability=0.9):
    quality = EvidenceQuality(
        source_reliability=reliability,
        integrity_authenticity=1.0,
        identity_mapping_confidence=1.0,
        completeness=1.0,
    )
    return Evidence(
        id=ev_id or f"ev_{kind.value}_{sorted(refs.items())}_{observed_at.isoformat()}",
        source=SRC,
        record_kind=kind,
        observed_at=observed_at,
        collected_at=ANCHOR,
        quality=quality,
        entity_references=tuple(sorted(refs.items())),
        payload=tuple(sorted(payload.items())),
    )


def identity_ev(identity_id="alice", **over):
    payload = {"name": "Alice", "identity_type": "human", "department": "Eng"}
    payload.update(over.pop("payload", {}))
    return ev(RecordKind.IDENTITY, {"identity_id": identity_id}, payload, **over)


def resource_ev(resource_id="db", **over):
    payload = {"name": "DB", "resource_type": "database", "sensitivity": "critical"}
    payload.update(over.pop("payload", {}))
    return ev(RecordKind.RESOURCE, {"resource_id": resource_id}, payload, **over)


def grant_ev(grant_id="g1", identity_id="alice", resource_id="db", **over):
    payload = {"action": "admin", "lifecycle": "standing"}
    payload.update(over.pop("payload", {}))
    return ev(
        RecordKind.PERMISSION_GRANT,
        {"grant_id": grant_id, "identity_id": identity_id, "resource_id": resource_id},
        payload,
        **over,
    )


def event_ev(event_id="e1", identity_id="alice", resource_id="db", **over):
    payload = {"action": "read", "success": True}
    payload.update(over.pop("payload", {}))
    return ev(
        RecordKind.ACTIVITY_EVENT,
        {"event_id": event_id, "identity_id": identity_id, "resource_id": resource_id},
        payload,
        **over,
    )


def normalize(records) -> Estate:
    return Normalizer().normalize(records)


# --- Happy path ---


def test_builds_all_entity_types():
    estate = normalize([identity_ev(), resource_ev(), grant_ev(), event_ev()])
    assert estate.issues == ()

    assert [i.id for i in estate.identities] == ["alice"]
    assert estate.identities[0].identity_type is IdentityType.HUMAN
    assert [r.id for r in estate.resources] == ["db"]
    assert estate.resources[0].sensitivity is Sensitivity.CRITICAL
    assert [e.id for e in estate.events] == ["e1"]

    perms = estate.identities[0].permissions
    assert [p.id for p in perms] == ["g1"]
    assert perms[0].action is Capability.ADMIN
    assert perms[0].lifecycle is GrantLifecycle.STANDING


def test_event_timestamp_uses_observed_not_collected():
    """
    Using collection time would shift a backfill into the present and light up
    every recency window at once.
    """
    observed = ANCHOR - timedelta(days=30)
    estate = normalize([identity_ev(), resource_ev(), event_ev(observed_at=observed)])
    assert estate.events[0].timestamp == observed


def test_lifecycle_and_timestamps_round_trip():
    expires = ANCHOR + timedelta(hours=4)
    granted = ANCHOR - timedelta(hours=1)
    estate = normalize(
        [
            identity_ev(),
            resource_ev(),
            grant_ev(
                payload={
                    "lifecycle": "elevated",
                    "granted_at": granted.isoformat(),
                    "expires_at": expires.isoformat(),
                }
            ),
        ]
    )
    perm = estate.identities[0].permissions[0]
    assert perm.lifecycle is GrantLifecycle.ELEVATED
    assert perm.expires_at == expires
    assert perm.confers_access_at(ANCHOR) is True
    assert perm.confers_access_at(expires + timedelta(minutes=1)) is False


# --- Deduplication ---


def test_identical_records_deduplicate_by_content_id():
    a = identity_ev(ev_id="ev_same")
    b = identity_ev(ev_id="ev_same")
    estate = normalize([a, b, resource_ev()])
    assert len(estate.identities) == 1
    assert len(estate.evidence_by_id) == 2  # identity + resource


# --- Conflict resolution ---


def test_latest_observation_wins():
    old = identity_ev(
        observed_at=ANCHOR - timedelta(days=2),
        ev_id="ev_old",
        payload={"department": "Finance"},
    )
    new = identity_ev(
        observed_at=ANCHOR, ev_id="ev_new", payload={"department": "Engineering"}
    )
    for order in ([old, new], [new, old]):
        estate = normalize(order)
        assert estate.identities[0].department == "Engineering"


def test_reliability_breaks_observation_ties():
    low = identity_ev(ev_id="ev_low", reliability=0.2, payload={"department": "Guess"})
    high = identity_ev(ev_id="ev_high", reliability=0.99, payload={"department": "Truth"})
    assert normalize([low, high]).identities[0].department == "Truth"
    assert normalize([high, low]).identities[0].department == "Truth"


def test_conflict_resolution_is_deterministic_under_reordering():
    records = [
        identity_ev(ev_id=f"ev_{i}", payload={"department": f"D{i}"}) for i in range(5)
    ]
    first = normalize(records).identities[0].department
    for _ in range(3):
        records.append(records.pop(0))
        assert normalize(records).identities[0].department == first


def test_losing_records_survive_in_provenance():
    """LWW discards a value, not the evidence. Both records remain citable."""
    old = identity_ev(observed_at=ANCHOR - timedelta(days=2), ev_id="ev_old")
    new = identity_ev(observed_at=ANCHOR, ev_id="ev_new")
    estate = normalize([old, new])
    assert estate.evidence_ids_for(RecordKind.IDENTITY, "alice") == ("ev_old", "ev_new")


# --- Provenance ---


def test_provenance_is_citation_ready_and_not_on_domain_objects():
    estate = normalize([identity_ev(), resource_ev(), grant_ev()])

    ids = estate.evidence_ids_for(RecordKind.PERMISSION_GRANT, "g1")
    assert len(ids) == 1
    assert estate.evidence_for(RecordKind.PERMISSION_GRANT, "g1")[0].id == ids[0]

    # The domain model stays free of ingestion concerns.
    assert not hasattr(estate.identities[0], "evidence_id")
    assert not hasattr(estate.identities[0].permissions[0], "evidence_id")


def test_provenance_for_unknown_entity_is_empty():
    estate = normalize([identity_ev()])
    assert estate.evidence_ids_for(RecordKind.IDENTITY, "nobody") == ()
    assert estate.identity("nobody") is None


# --- Malformed input never raises ---


def test_missing_payload_key_becomes_an_issue():
    bad = ev(RecordKind.RESOURCE, {"resource_id": "db"}, {"name": "DB"})
    estate = normalize([bad])
    assert estate.resources == ()
    assert len(estate.issues) == 1
    assert "resource_type" in estate.issues[0].reason


def test_unknown_enum_value_becomes_an_issue():
    estate = normalize([identity_ev(payload={"identity_type": "martian"})])
    assert estate.identities == ()
    assert "martian" in estate.issues[0].reason


def test_missing_entity_reference_becomes_an_issue():
    bad = ev(RecordKind.IDENTITY, {"wrong_key": "alice"}, {"name": "A"})
    estate = normalize([bad])
    assert estate.identities == ()
    assert "identity_id" in estate.issues[0].reason


def test_naive_timestamp_in_payload_becomes_an_issue():
    estate = normalize(
        [
            identity_ev(),
            resource_ev(),
            grant_ev(payload={"granted_at": "2026-09-01T00:00:00"}),  # no offset
        ]
    )
    assert estate.identities[0].permissions == ()
    assert any("timezone-aware" in i.reason for i in estate.issues)


def test_permission_invariant_violation_becomes_an_issue():
    """time_bound with no expiry is a standing grant lying about itself."""
    estate = normalize(
        [identity_ev(), resource_ev(), grant_ev(payload={"lifecycle": "time_bound"})]
    )
    assert estate.identities[0].permissions == ()
    assert any("expires_at" in i.reason for i in estate.issues)


def test_one_bad_record_does_not_sink_the_batch():
    good = [identity_ev(), resource_ev(), event_ev()]
    bad = ev(RecordKind.RESOURCE, {"resource_id": "broken"}, {"name": "x"})
    estate = normalize(good + [bad])
    assert len(estate.identities) == 1
    assert len(estate.events) == 1
    assert len(estate.issues) == 1


def test_policy_documents_are_kept_as_citations():
    """The connector resolves them; the normalizer keeps them for findings to cite."""
    doc = ev(RecordKind.POLICY_DOCUMENT, {"policy_id": "pol-admin"}, {"document": "{}"})
    estate = normalize([doc])
    assert estate.issues == ()
    assert estate.evidence_ids_for(RecordKind.POLICY_DOCUMENT, "pol-admin") == (doc.id,)


def test_a_grant_cites_the_policies_it_was_derived_from():
    doc = ev(RecordKind.POLICY_DOCUMENT, {"policy_id": "pol-admin"}, {"document": "{}"})
    g = grant_ev(payload={"derived_from": ["pol-admin"]})
    estate = normalize([identity_ev(), resource_ev(), g, doc])
    assert estate.evidence_ids_for(RecordKind.PERMISSION_GRANT, "g1") == (g.id, doc.id)


def test_a_policy_document_without_an_id_is_an_issue():
    doc = ev(RecordKind.POLICY_DOCUMENT, {"resource_id": "db"}, {"document": "{}"})
    assert "policy_id" in normalize([doc]).issues[0].reason


# --- Dangling references ---


def test_grant_to_unknown_resource_is_retained_with_an_issue():
    """
    Understating access is the one direction a privilege engine must not err in,
    so the grant is kept and the gap is reported.
    """
    estate = normalize([identity_ev(), grant_ev(resource_id="ghost")])
    assert [p.id for p in estate.identities[0].permissions] == ["g1"]
    assert any("unknown resource" in i.reason for i in estate.issues)


def test_grant_to_unknown_identity_is_reported():
    estate = normalize([resource_ev(), grant_ev(identity_id="ghost")])
    assert estate.identities == ()
    assert any("unknown identity" in i.reason for i in estate.issues)


# --- End to end against the synthetic connector ---


def test_normalizes_the_full_scenario_set_cleanly():
    connector = SyntheticConnector(anchor_time=ANCHOR)
    estate = normalize(connector.collect())

    assert estate.issues == (), [i.reason for i in estate.issues]
    # Every labelled subject must survive to the domain layer: ground truth that
    # names an identity the normalizer dropped would silently score as a miss.
    labelled = {f.subject_id for f in connector.expected_findings()}
    assert labelled <= {i.id for i in estate.identities}
    assert estate.events
    # Everyone holds something -- except a role at the end of a broken chain,
    # whose emptiness is the point of the scenario (`broken_chain`, and FRESH
    # v3's emptied sequencer role). A person or service holding nothing would
    # mean a grant was lost in normalization.
    empty = [i for i in estate.identities if not i.permissions]
    assert empty and all(i.identity_type is IdentityType.ROLE for i in empty)


def test_every_grant_is_citable_end_to_end():
    """The chain the engine exists for: finding -> grant -> the record that proved it."""
    estate = normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    for identity in estate.identities:
        for perm in identity.permissions:
            cited = estate.evidence_ids_for(RecordKind.PERMISSION_GRANT, perm.id)
            assert cited, f"{perm.id} has no evidence"
            assert all(c in estate.evidence_by_id for c in cited)


def test_dormant_admin_scenario_survives_normalization():
    scenario = next(s for s in SCENARIOS if s.name == "dormant_standing_admin")
    estate = normalize(
        SyntheticConnector(anchor_time=ANCHOR, scenarios=[scenario]).collect()
    )
    alice = estate.identity("alice")
    admin = next(p for p in alice.permissions if p.action is Capability.ADMIN)

    assert admin.is_standing
    assert admin.confers_access_at(ANCHOR)
    assert estate.resource(admin.resource_id).sensitivity is Sensitivity.CRITICAL
    # She is active, but never on the resource she holds admin over.
    assert all(e.resource_id != admin.resource_id for e in estate.events)


def test_filler_volume_normalizes_without_issues():
    estate = normalize(
        SyntheticConnector(anchor_time=ANCHOR, filler_identities=40).collect()
    )
    assert estate.issues == (), [i.reason for i in estate.issues[:5]]
    scenario_identities = len(
        normalize(SyntheticConnector(anchor_time=ANCHOR).collect()).identities
    )
    assert len(estate.identities) == scenario_identities + 40


def test_pipeline_reaches_feature_extraction():
    """connector -> normalizer -> features, with no hand-built fixtures anywhere."""
    from app.risk.features import FeatureExtractor

    estate = normalize(
        SyntheticConnector(anchor_time=ANCHOR, filler_identities=40).collect()
    )
    alice = estate.identity("alice")
    features = FeatureExtractor.extract_features(
        alice, estate.resources, estate.events, ANCHOR
    )
    assert features.standing_permission_count == 1
    assert features.standing_critical_permission_count == 1
    # Alice is busy, just never on the grant she holds admin over. An
    # identity-level "last privileged use" cannot see that.
    assert features.total_event_count > 0
    assert features.days_since_last_privileged_use is None

    # Expiring grants that outlived their expiry usually mean revocation failed.
    expired = sum(
        FeatureExtractor.extract_features(
            i, estate.resources, estate.events, ANCHOR
        ).expired_permission_count
        for i in estate.identities
    )
    assert expired > 0

    jit = sum(
        FeatureExtractor.extract_features(
            i, estate.resources, estate.events, ANCHOR
        ).jit_eligible_permission_count
        for i in estate.identities
    )
    assert jit > 0
