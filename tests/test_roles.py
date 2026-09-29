"""
Roles as principals.

A role has two sides: a resource you are granted (impersonate on it) and an
identity that holds grants of its own. `Resource.principal_id` is the only
thing joining them. These tests pin how that link is ingested, and that roles
stay out of the per-identity engine until the graph layer judges them.
"""

from app.evidence.models import RecordKind
from app.models.identity import IdentityType
from app.models.capability import Capability
from app.risk.baselines import PeerBaseline
from app.risk.engine import RiskEngine
from tests.test_normalize import (
    ANCHOR,
    grant_ev,
    identity_ev,
    normalize,
    resource_ev,
)


def role_estate():
    """irene may assume the finance admin role; the role holds admin on the ledger."""
    return normalize(
        [
            identity_ev("irene", payload={"department": "Finance"}),
            resource_ev(
                "finance_admin_role",
                payload={"resource_type": "cloud_account", "sensitivity": "high",
                         "principal_id": "role_finance_admin"},
            ),
            grant_ev("g_irene_role", "irene", "finance_admin_role",
                     payload={"action": "impersonate"}),
            identity_ev("role_finance_admin",
                        payload={"identity_type": "role", "department": "Finance"}),
            resource_ev("ledger"),
            grant_ev("g_role_ledger", "role_finance_admin", "ledger"),
        ]
    )


# --- Ingestion -------------------------------------------------------------


def test_role_is_an_identity_that_holds_grants():
    estate = role_estate()
    assert estate.issues == ()
    role = estate.identity("role_finance_admin")
    assert role.identity_type is IdentityType.ROLE
    assert [(p.resource_id, p.action) for p in role.permissions] == [
        ("ledger", Capability.ADMIN)
    ]


def test_role_resource_points_at_its_principal():
    estate = role_estate()
    assert estate.resource("finance_admin_role").principal_id == "role_finance_admin"
    assert estate.resource("finance_admin_role").is_assumable
    assert estate.resource("ledger").principal_id is None
    assert not estate.resource("ledger").is_assumable


def test_link_to_unknown_principal_is_retained_with_an_issue():
    """Dropping the link would erase every path through the role."""
    estate = normalize(
        [resource_ev("orphan_role", payload={"principal_id": "ghost_role"})]
    )
    assert estate.resource("orphan_role").principal_id == "ghost_role"
    [issue] = estate.issues
    assert issue.record_kind is RecordKind.RESOURCE
    assert "ghost_role" in issue.reason
    assert issue.evidence_id in estate.evidence_ids_for(RecordKind.RESOURCE, "orphan_role")


def test_malformed_link_becomes_an_issue():
    estate = normalize([resource_ev("bad_role", payload={"principal_id": ""})])
    assert estate.resources == ()
    assert "principal_id" in estate.issues[0].reason


def test_a_link_need_not_point_at_a_role():
    """Impersonating a service account is the same edge as assuming a role."""
    estate = normalize(
        [
            resource_ev("svc_deployer_sa", payload={"principal_id": "svc_deployer"}),
            identity_ev("svc_deployer", payload={"identity_type": "service"}),
        ]
    )
    assert estate.issues == ()
    assert estate.resource("svc_deployer_sa").principal_id == "svc_deployer"


# --- Control planes: `governs` -------------------------------------------


def test_governs_is_sorted_and_deduplicated():
    """Order in the source is not data."""
    estate = normalize(
        [
            resource_ev("console", payload={"governs": ["ledger", "db", "ledger"]}),
            resource_ev("ledger"),
            resource_ev("db"),
        ]
    )
    assert estate.issues == ()
    assert estate.resource("console").governs == ("db", "ledger")
    assert estate.resource("db").governs == ()


def test_governing_an_unknown_resource_is_retained_with_an_issue():
    estate = normalize([resource_ev("console", payload={"governs": ["ghost_db"]})])
    assert estate.resource("console").governs == ("ghost_db",)
    [issue] = estate.issues
    assert "ghost_db" in issue.reason


def test_malformed_governs_becomes_an_issue():
    for bad in ("ledger", ["ledger", ""], [3]):
        estate = normalize([resource_ev("console", payload={"governs": bad})])
        assert estate.resources == ()
        assert "governs" in estate.issues[0].reason


# --- Kept out of the per-identity engine -----------------------------------


def test_engine_does_not_assess_roles():
    """
    Nobody logs in as a role, so the staleness rules would call every role
    dormant. Its grants count against whoever can reach it instead.
    """
    results = RiskEngine().assess_estate(role_estate(), ANCHOR)
    assert [r.identity_id for r in results] == ["irene"]


def test_peer_baseline_ignores_roles():
    """A role is not a colleague: it must not vouch for its department."""
    peers = PeerBaseline.build(role_estate().identities)
    assert peers.other_holders("ledger", "anyone") == ()
    assert peers.other_holders("finance_admin_role", "anyone") == (("irene", "Finance"),)
