"""
Secret-path scoping (standing_secret_access.v2): a grant scoped to a path in a
secret store is a workload reading its own secrets; an unscoped one is the
whole store.
"""

import pytest

from app.models.capability import Capability
from app.models.permission import Permission
from app.risk.detections import StandingPrivilegeOnHighValue, StandingSecretAccess
from app.risk.engine import RiskEngine
from tests.test_normalize import ANCHOR, grant_ev, identity_ev, normalize, resource_ev


def estate(action="read", **grant_payload):
    return normalize([
        identity_ev("svc", payload={"identity_type": "service"}),
        resource_ev("vault", payload={"resource_type": "secret_store", "sensitivity": "high"}),
        grant_ev("g", "svc", "vault", payload={"action": action, **grant_payload}),
    ])


def fired(est, rule):
    [r] = RiskEngine(rules=[rule]).assess_estate(est, ANCHOR)
    return bool(r.assessment.triggered_factors or r.suppressed)


def test_the_scope_is_carried_from_the_source():
    est = estate(scope="kv/routing-api/*")
    assert est.identity("svc").permissions[0].scope == "kv/routing-api/*"
    assert estate().identity("svc").permissions[0].scope is None


def test_an_unscoped_read_is_the_whole_store():
    assert fired(estate(), StandingSecretAccess())


def test_a_scoped_read_is_the_workloads_own_secrets():
    assert not fired(estate(scope="kv/routing-api/*"), StandingSecretAccess())


def test_scope_never_hides_admin_on_the_store():
    """Admin on a HIGH store is the privilege rule's finding, scoped or not."""
    assert fired(estate("admin", scope="kv/routing-api/*"), StandingPrivilegeOnHighValue())


@pytest.mark.parametrize("bad, exc", [("", ValueError), ("  ", ValueError), (3, TypeError)])
def test_a_scope_must_be_a_non_empty_string(bad, exc):
    with pytest.raises(exc):
        Permission(id="g", identity_id="a", resource_id="r", action=Capability.READ, scope=bad)
