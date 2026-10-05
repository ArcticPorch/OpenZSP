"""
Identity, Resource and Event are frozen and validate themselves (2026-10-05),
like Permission. Bad input raises TypeError for a wrong type and ValueError for
a well-typed but unacceptable value; the normalizer turns either into an issue.
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from app.models.capability import Capability
from app.models.event import Event, EventAction
from app.models.identity import Identity, IdentityType
from app.models.permission import Permission
from app.models.resource import Resource, ResourceType, Sensitivity
from tests.test_normalize import identity_ev, normalize, resource_ev

T = datetime(2026, 9, 9, tzinfo=timezone.utc)


def ident(**over):
    fields = dict(id="a", name="A", identity_type=IdentityType.HUMAN, department="Eng")
    fields.update(over)
    return Identity(**fields)


def perm(identity_id="a"):
    return Permission(id="g", identity_id=identity_id, resource_id="r", action=Capability.READ)


def test_identity_is_frozen_and_hashable_with_a_permission_tuple():
    i = ident(permissions=[perm()])
    assert i.permissions == (perm(),)
    assert hash(i)
    with pytest.raises(FrozenInstanceError):
        i.department = "Sales"


@pytest.mark.parametrize("over, exc", [
    ({"name": ""}, ValueError),
    ({"identity_type": "human"}, TypeError),
    ({"is_external": "yes"}, TypeError),
    ({"department": " "}, ValueError),
    ({"org_path": ""}, ValueError),
    ({"permissions": "g"}, TypeError),
])
def test_identity_rejects_bad_fields(over, exc):
    with pytest.raises(exc):
        ident(**over)


def test_a_grant_must_belong_to_its_identity():
    with pytest.raises(ValueError, match="belongs to 'b'"):
        ident(permissions=[perm("b")])


def test_resource_validates_and_freezes_governs():
    r = Resource("r", "R", ResourceType.DATABASE, Sensitivity.HIGH, governs=["x", "y"])
    assert r.governs == ("x", "y") and hash(r)
    with pytest.raises(TypeError):
        Resource("r", "R", ResourceType.DATABASE, "high")
    with pytest.raises(ValueError):
        Resource("r", "R", ResourceType.DATABASE, Sensitivity.HIGH, principal_id="")


def test_event_rejects_a_naive_timestamp_where_it_is_made():
    with pytest.raises(ValueError):
        Event("e", "a", "r", EventAction.READ, datetime(2026, 9, 9), True)
    with pytest.raises(TypeError):
        Event("e", "a", "r", EventAction.READ, T, "true")


def test_the_normalizer_turns_validation_failures_into_issues():
    """One bad record must not sink the batch, now that models validate themselves."""
    estate = normalize([identity_ev(payload={"name": ""}), resource_ev()])
    assert estate.identities == ()
    assert len(estate.resources) == 1
    assert any("name" in i.reason for i in estate.issues)
