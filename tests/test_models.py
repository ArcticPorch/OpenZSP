from app.models.identity import Identity, IdentityType


def test_identity_creation():
    alice = Identity(
        id="user_001",
        name="Alice",
        identity_type=IdentityType.HUMAN,
        department="engineering"
    )

    assert alice.id == "user_001"
    assert alice.name == "Alice"
    assert alice.identity_type == IdentityType.HUMAN
    assert alice.department == "engineering"

from app.models.resource import Resource, ResourceType, Sensitivity


def test_resource_creation():
    production_db = Resource(
        id="res_001",
        name="production-db",
        resource_type=ResourceType.DATABASE,
        sensitivity=Sensitivity.CRITICAL
    )

    assert production_db.name == "production-db"
    assert production_db.resource_type == ResourceType.DATABASE
    assert production_db.sensitivity == Sensitivity.CRITICAL

from app.models.capability import Capability
from app.models.permission import GrantLifecycle, Permission


def test_permission_creation():
    permission = Permission(
        id="perm_001",
        identity_id="user_001",
        resource_id="res_001",
        action=Capability.ADMIN,
        lifecycle=GrantLifecycle.STANDING
    )

    assert permission.identity_id == "user_001"
    assert permission.resource_id == "res_001"
    assert permission.action == Capability.ADMIN
    assert permission.lifecycle is GrantLifecycle.STANDING
    assert permission.is_standing is True

from datetime import datetime, timezone

from app.models.event import Event, EventAction


def test_event_creation():
    event = Event(
        id="event_001",
        identity_id="user_001",
        resource_id="res_001",
        action=EventAction.READ,
        timestamp=datetime.now(timezone.utc),
        success=True
    )

    assert event.identity_id == "user_001"
    assert event.resource_id == "res_001"
    assert event.action == EventAction.READ
    assert event.success is True

