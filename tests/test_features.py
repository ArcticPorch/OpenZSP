from datetime import datetime, timezone, timedelta
import pytest

from app.models.identity import Identity, IdentityType
from app.models.capability import Capability
from app.models.permission import GrantLifecycle, Permission
from app.models.resource import Resource, ResourceType, Sensitivity
from app.models.event import Event, EventAction
from app.risk.features import FeatureExtractor, IdentityFeatures


def test_datetime_validation():
    # Naive evaluation_time rejected
    identity = Identity(
        id="user_1",
        name="Alice",
        identity_type=IdentityType.HUMAN,
        department="Engineering",
    )
    with pytest.raises(ValueError):
        FeatureExtractor.extract_features(
            identity=identity,
            resources=[],
            events=[],
            evaluation_time=datetime.now(),  # naive datetime
        )

    # Timezone-aware evaluation_time accepted
    features = FeatureExtractor.extract_features(
        identity=identity,
        resources=[],
        events=[],
        evaluation_time=datetime.now(timezone.utc),
    )
    assert isinstance(features, IdentityFeatures)


def test_permissions_extraction():
    # Setup resources
    res_critical = Resource(
        id="res_crit",
        name="Production DB",
        resource_type=ResourceType.DATABASE,
        sensitivity=Sensitivity.CRITICAL,
    )
    res_non_critical = Resource(
        id="res_non_crit",
        name="Sandbox DB",
        resource_type=ResourceType.DATABASE,
        sensitivity=Sensitivity.MEDIUM,
    )
    resources = [res_critical, res_non_critical]

    # 1. No permissions
    identity_no_perms = Identity(
        id="user_no_perms",
        name="No Perms",
        identity_type=IdentityType.HUMAN,
        department="Engineering",
        permissions=[],
    )
    eval_time = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)
    f_no = FeatureExtractor.extract_features(identity_no_perms, resources, [], eval_time)
    assert f_no.total_permission_count == 0
    assert f_no.standing_permission_count == 0
    assert f_no.temporary_permission_count == 0
    assert f_no.privileged_permission_count == 0
    assert f_no.critical_resource_permission_count == 0
    assert f_no.standing_critical_permission_count == 0

    # 2. Mix of permissions
    # - non-standing permission (JIT-eligible)
    p_temp = Permission(
        id="p1",
        identity_id="user_mix",
        resource_id="res_non_crit",
        action=Capability.READ,
        lifecycle=GrantLifecycle.JIT_ELIGIBLE,
    )
    # - standing permission
    p_standing = Permission(
        id="p2",
        identity_id="user_mix",
        resource_id="res_non_crit",
        action=Capability.READ,
        lifecycle=GrantLifecycle.STANDING,
    )
    # - privileged permission (action = Capability.DEPLOY, standing)
    p_privileged = Permission(
        id="p3",
        identity_id="user_mix",
        resource_id="res_non_crit",
        action=Capability.DEPLOY,
        lifecycle=GrantLifecycle.STANDING,
    )
    # - critical resource permission (action = READ, JIT-eligible)
    p_critical = Permission(
        id="p4",
        identity_id="user_mix",
        resource_id="res_crit",
        action=Capability.READ,
        lifecycle=GrantLifecycle.JIT_ELIGIBLE,
    )
    # - standing critical permission (action = READ)
    p_standing_critical = Permission(
        id="p5",
        identity_id="user_mix",
        resource_id="res_crit",
        action=Capability.READ,
        lifecycle=GrantLifecycle.STANDING,
    )
    # - missing resource permission
    p_missing_res = Permission(
        id="p6",
        identity_id="user_mix",
        resource_id="res_missing_unknown",
        action=Capability.WRITE,
        lifecycle=GrantLifecycle.STANDING,
    )

    identity_mix = Identity(
        id="user_mix",
        name="Mix Perms",
        identity_type=IdentityType.HUMAN,
        department="Engineering",
        permissions=[p_temp, p_standing, p_privileged, p_critical, p_standing_critical, p_missing_res],
    )

    f_mix = FeatureExtractor.extract_features(identity_mix, resources, [], eval_time)
    assert f_mix.total_permission_count == 6
    assert f_mix.temporary_permission_count == 2  # p_temp, p_critical
    assert f_mix.standing_permission_count == 4   # p_standing, p_privileged, p_standing_critical, p_missing_res
    assert f_mix.privileged_permission_count == 1  # p_privileged (DEPLOY)
    assert f_mix.critical_resource_permission_count == 2  # p_critical, p_standing_critical
    assert f_mix.standing_critical_permission_count == 1  # p_standing_critical


def test_events_time_and_temporal_features():
    identity = Identity(
        id="user_event",
        name="Event Tester",
        identity_type=IdentityType.HUMAN,
        department="Engineering",
        permissions=[],
    )
    eval_time = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)

    res_crit = Resource(
        id="res_crit",
        name="Critical Res",
        resource_type=ResourceType.DATABASE,
        sensitivity=Sensitivity.CRITICAL,
    )
    resources = [res_crit]

    # 1. No events
    f_none = FeatureExtractor.extract_features(identity, resources, [], eval_time)
    assert f_none.total_event_count == 0
    assert f_none.failed_event_count == 0
    assert f_none.failed_authentication_count == 0
    assert f_none.recent_admin_action_count == 0
    assert f_none.recent_event_count_24h == 0
    assert f_none.recent_event_count_7d == 0
    assert f_none.last_event_timestamp is None
    assert f_none.last_privileged_event_timestamp is None
    assert f_none.days_since_last_privileged_use is None

    # 2. Comprehensive Event Log
    # Successful event (inside 24h)
    ev_success = Event(
        id="ev_succ",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.READ,
        timestamp=eval_time - timedelta(hours=2),
        success=True,
    )
    # Failed event (inside 24h)
    ev_failed = Event(
        id="ev_fail",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.WRITE,
        timestamp=eval_time - timedelta(hours=3),
        success=False,
    )
    # Failed LOGIN (inside 24h)
    ev_failed_login = Event(
        id="ev_fail_login",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.LOGIN,
        timestamp=eval_time - timedelta(hours=4),
        success=False,
    )
    # Successful LOGIN (inside 24h, privileged)
    ev_succ_login = Event(
        id="ev_succ_login",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.LOGIN,
        timestamp=eval_time - timedelta(hours=5),
        success=True,
    )
    # Recent administrative event (inside 24h)
    ev_recent_admin = Event(
        id="ev_recent_admin",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.ASSUME_ROLE,
        timestamp=eval_time - timedelta(hours=6),
        success=True,
    )
    # Old administrative event (outside 24h, inside 7d)
    ev_old_admin = Event(
        id="ev_old_admin",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.GRANT_PERMISSION,
        timestamp=eval_time - timedelta(hours=26),
        success=True,
    )
    # Event belonging to another identity
    ev_other = Event(
        id="ev_other",
        identity_id="user_other",
        resource_id="res_non_crit",
        action=EventAction.READ,
        timestamp=eval_time - timedelta(hours=1),
        success=True,
    )
    # Future event (timestamp > eval_time)
    ev_future = Event(
        id="ev_future",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.DELETE,
        timestamp=eval_time + timedelta(hours=1),
        success=True,
    )
    # Event exactly on 24h boundary
    ev_24h_boundary = Event(
        id="ev_24h_bound",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.READ,
        timestamp=eval_time - timedelta(hours=24),
        success=True,
    )
    # Event just outside 24h
    ev_just_outside_24h = Event(
        id="ev_just_out_24h",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.READ,
        timestamp=eval_time - timedelta(hours=24, seconds=1),
        success=True,
    )
    # Event inside 7d
    ev_inside_7d = Event(
        id="ev_in_7d",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.READ,
        timestamp=eval_time - timedelta(days=3),
        success=True,
    )
    # Event exactly on 7d boundary
    ev_7d_boundary = Event(
        id="ev_7d_bound",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.READ,
        timestamp=eval_time - timedelta(days=7),
        success=True,
    )
    # Event just outside 7d
    ev_just_outside_7d = Event(
        id="ev_just_out_7d",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.READ,
        timestamp=eval_time - timedelta(days=7, seconds=1),
        success=True,
    )
    # Event exactly at evaluation_time
    ev_at_eval = Event(
        id="ev_at_eval",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.READ,
        timestamp=eval_time,
        success=True,
    )

    events_list = [
        ev_success,
        ev_failed,
        ev_failed_login,
        ev_succ_login,
        ev_recent_admin,
        ev_old_admin,
        ev_other,
        ev_future,
        ev_24h_boundary,
        ev_just_outside_24h,
        ev_inside_7d,
        ev_7d_boundary,
        ev_just_outside_7d,
        ev_at_eval,
    ]

    features = FeatureExtractor.extract_features(identity, resources, events_list, eval_time)

    # total_event_count must NOT count future events or other identity events
    # Expected included (11 events):
    # - ev_success (eval - 2h)
    # - ev_failed (eval - 3h)
    # - ev_failed_login (eval - 4h)
    # - ev_succ_login (eval - 5h)
    # - ev_recent_admin (eval - 6h)
    # - ev_old_admin (eval - 26h)
    # - ev_24h_boundary (eval - 24h)
    # - ev_just_outside_24h (eval - 24h 1s)
    # - ev_inside_7d (eval - 3d)
    # - ev_7d_boundary (eval - 7d)
    # - ev_at_eval (eval)
    # Future event (ev_future) and other user (ev_other) and event just outside 7d (ev_just_outside_7d) are ignored or outside 7d boundary but ev_just_outside_7d still counts in total_event_count because it's in history!
    # Wait, ev_just_outside_7d (eval - 7d 1s) is in the past, so it DOES count in total_event_count.
    # Total historical events for this user = 12 events (all except ev_future and ev_other).
    assert features.total_event_count == 12

    # Failed event count: ev_failed (1) + ev_failed_login (1) = 2
    assert features.failed_event_count == 2

    # Failed auth count: ev_failed_login (1) = 1
    assert features.failed_authentication_count == 1

    # Recent admin actions (within 24h): ev_recent_admin (ASSUME_ROLE inside 24h) = 1.
    # ev_old_admin is ASSUME_ROLE/GRANT_PERMISSION but outside 24h, so it's not "recent".
    assert features.recent_admin_action_count == 1

    # Events in 24h:
    # - ev_success (2h)
    # - ev_failed (3h)
    # - ev_failed_login (4h)
    # - ev_succ_login (5h)
    # - ev_recent_admin (6h)
    # - ev_24h_boundary (24h)
    # - ev_at_eval (0h)
    # Total = 7
    assert features.recent_event_count_24h == 7

    # Events in 7d:
    # All 24h events (7) + ev_old_admin (26h) + ev_just_outside_24h (24h 1s) + ev_inside_7d (3d) + ev_7d_boundary (7d).
    # Total = 7 + 4 = 11.
    assert features.recent_event_count_7d == 11

    # last_event_timestamp should be ev_at_eval (exactly eval_time)
    assert features.last_event_timestamp == eval_time

    # Privileged events: ev_recent_admin (ASSUME_ROLE, 6h), ev_old_admin (GRANT_PERMISSION, 26h).
    # What about login? LOGIN is considered privileged event in features.py:
    # `is_privileged_event = ev.action in ADMIN_EVENT_ACTIONS or ev.action == EventAction.DELETE`
    # Wait, the comment says: "EventActions like login, admin actions (assume_role, grant/revoke) are considered privileged."
    # Let's check the code implementation:
    # `is_privileged_event = (ev.action in ADMIN_EVENT_ACTIONS or ev.action == EventAction.DELETE)`
    # It does NOT include login in the code logic! It only includes ADMIN_EVENT_ACTIONS and DELETE.
    # So the privileged events are:
    # - ev_recent_admin (ASSUME_ROLE, 6h)
    # - ev_old_admin (GRANT_PERMISSION, 26h)
    # The latest is ev_recent_admin (6h ago).
    assert features.last_privileged_event_timestamp == eval_time - timedelta(hours=6)

    # Days since last privileged use: delta is 6 hours, 6/24 = 0.25 days
    assert features.days_since_last_privileged_use == pytest.approx(0.25)


def test_privileged_activity_at_evaluation_time():
    identity = Identity(
        id="user_event",
        name="Event Tester",
        identity_type=IdentityType.HUMAN,
        department="Engineering",
        permissions=[],
    )
    eval_time = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)

    # Privileged action exactly at evaluation time
    ev_admin = Event(
        id="ev_admin_at_eval",
        identity_id="user_event",
        resource_id="res_non_crit",
        action=EventAction.ASSUME_ROLE,
        timestamp=eval_time,
        success=True,
    )
    features = FeatureExtractor.extract_features(identity, [], [ev_admin], eval_time)
    assert features.last_privileged_event_timestamp == eval_time
    assert features.days_since_last_privileged_use == pytest.approx(0.0)


def test_resource_access_features():
    identity = Identity(
        id="user_res",
        name="Resource Tester",
        identity_type=IdentityType.HUMAN,
        department="Engineering",
        permissions=[],
    )
    eval_time = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)

    res_crit_1 = Resource(
        id="res_crit_1",
        name="Crit 1",
        resource_type=ResourceType.DATABASE,
        sensitivity=Sensitivity.CRITICAL,
    )
    res_crit_2 = Resource(
        id="res_crit_2",
        name="Crit 2",
        resource_type=ResourceType.DATABASE,
        sensitivity=Sensitivity.CRITICAL,
    )
    res_non_crit = Resource(
        id="res_non_crit",
        name="Non Crit",
        resource_type=ResourceType.DATABASE,
        sensitivity=Sensitivity.LOW,
    )
    resources = [res_crit_1, res_crit_2, res_non_crit]

    # Events accessing:
    # - one resource
    # - repeated access to same resource
    # - multiple unique resources
    # - critical resource
    # - non-critical resource
    # - missing/unknown resource
    events = [
        # Repeated access to res_non_crit
        Event("e1", "user_res", "res_non_crit", EventAction.READ, eval_time - timedelta(hours=1), True),
        Event("e2", "user_res", "res_non_crit", EventAction.WRITE, eval_time - timedelta(hours=2), True),
        # Access to res_crit_1
        Event("e3", "user_res", "res_crit_1", EventAction.READ, eval_time - timedelta(hours=3), True),
        # Access to missing/unknown resource
        Event("e4", "user_res", "res_unknown", EventAction.READ, eval_time - timedelta(hours=4), True),
    ]

    features = FeatureExtractor.extract_features(identity, resources, events, eval_time)

    # Unique resources: res_non_crit, res_crit_
    assert features.unique_resource_count_accessed == 3

    # Critical resources: res_crit_1 = 1 (res_unknown must NOT automatically be treated as critical)
    assert features.critical_resource_count_accessed == 1


def test_determinism():
    identity = Identity(
        id="user_mix",
        name="Mix Perms",
        identity_type=IdentityType.HUMAN,
        department="Engineering",
        permissions=[
            Permission(
                "p1",
                "user_mix",
                "res_crit",
                Capability.READ,
                GrantLifecycle.STANDING,
            )
        ],
    )
    res_crit = Resource("res_crit", "Crit", ResourceType.DATABASE, Sensitivity.CRITICAL)
    eval_time = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        Event("e1", "user_mix", "res_crit", EventAction.READ, eval_time - timedelta(hours=1), True)
    ]

    features_1 = FeatureExtractor.extract_features(identity, [res_crit], events, eval_time)
    features_2 = FeatureExtractor.extract_features(identity, [res_crit], events, eval_time)

    assert features_1 == features_2
