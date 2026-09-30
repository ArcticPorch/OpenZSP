"""
Effective reach: every (resource, capability) labelled with the easiest tier
that reaches it -- standing, temporary, expired-attached or JIT-only.
"""

from datetime import timedelta

import pytest

from app.connectors.synthetic import SyntheticConnector
from app.graph.effective import ReachTier, effective_reach, grant_tier
from app.graph.graph import IdentityGraph
from app.graph.reach import any_grant, reach
from app.models.capability import Capability
from app.models.permission import GrantLifecycle, Permission
from app.normalize.normalizer import Normalizer
from tests.test_normalize import ANCHOR
from tests.test_reach import grant, graph_of, ids, person, res, role

A, READ, WRITE = Capability.ADMIN, Capability.READ, Capability.WRITE
STANDING, TEMPORARY = ReachTier.STANDING, ReachTier.TEMPORARY
EXPIRED, JIT = ReachTier.EXPIRED_ATTACHED, ReachTier.JIT_ONLY


def iso(**delta):
    return (ANCHOR + timedelta(**delta)).isoformat()


LIVE_ELEVATION = {"lifecycle": "elevated", "granted_at": iso(hours=-1), "expires_at": iso(hours=3)}
EXPIRED_GRANT = {"lifecycle": "time_bound", "expires_at": iso(days=-30)}
JIT_GRANT = {"lifecycle": "jit_eligible"}


def four_tiers():
    """bob holds one of each: standing, a live elevation, an expired grant, a JIT hop."""
    return graph_of(
        person("bob"), role("prod_role"),
        res("ledger"), res("vault"), res("billing"),
        res("prod_role_res", principal_id="prod_role"), res("prod"),
        grant("g_ledger", "bob", "ledger"),
        grant("g_vault", "bob", "vault", "read", **LIVE_ELEVATION),
        grant("g_billing", "bob", "billing", "write", **EXPIRED_GRANT),
        grant("g_jit", "bob", "prod_role_res", "impersonate", **JIT_GRANT),
        grant("g_prod", "prod_role", "prod"),
    )


def eff(graph, who="bob", max_hops=4):
    return effective_reach(graph, who, at=ANCHOR, max_hops=max_hops)


# --- One grant ---------------------------------------------------------------


def perm(lifecycle, **times):
    return Permission(id="g", identity_id="a", resource_id="r", action=READ,
                      lifecycle=lifecycle, **times)


@pytest.mark.parametrize(
    "p, tier",
    [
        (perm(GrantLifecycle.STANDING), STANDING),
        (perm(GrantLifecycle.TIME_BOUND, expires_at=ANCHOR + timedelta(days=5)), TEMPORARY),
        (perm(GrantLifecycle.ELEVATED, granted_at=ANCHOR - timedelta(hours=1),
              expires_at=ANCHOR + timedelta(hours=3)), TEMPORARY),
        (perm(GrantLifecycle.TIME_BOUND, expires_at=ANCHOR - timedelta(days=1)), EXPIRED),
        (perm(GrantLifecycle.JIT_ELIGIBLE), JIT),
        # Scheduled: live later with no approval, but not now. Something has
        # still to happen, so it sits with JIT rather than with what works today.
        (perm(GrantLifecycle.TIME_BOUND, granted_at=ANCHOR + timedelta(days=1),
              expires_at=ANCHOR + timedelta(days=2)), JIT),
    ],
)
def test_grant_tier(p, tier):
    assert grant_tier(p, ANCHOR) is tier


def test_tiers_are_ordered_by_what_has_to_go_right():
    assert [t.rank for t in (STANDING, TEMPORARY, EXPIRED, JIT)] == [0, 1, 2, 3]


# --- Tiers across an identity --------------------------------------------------


def test_each_resource_is_labelled_with_its_tier():
    r = eff(four_tiers())
    assert r.get("ledger", A).tier is STANDING
    assert r.get("vault", READ).tier is TEMPORARY
    assert r.get("billing", WRITE).tier is EXPIRED
    assert r.get("prod", A).tier is JIT
    assert r.get("prod_role_res", Capability.IMPERSONATE).tier is JIT


def test_at_most_is_cumulative():
    r = eff(four_tiers())
    assert r.resource_ids(STANDING) == ("ledger",)
    assert r.resource_ids(TEMPORARY) == ("ledger", "vault")
    assert r.resource_ids(EXPIRED) == ("billing", "ledger", "vault")
    assert r.resource_ids(JIT) == ("billing", "ledger", "prod", "prod_role_res", "vault")
    assert r.resource_ids() == r.resource_ids(JIT)


def test_principals_are_tiered_too():
    [p] = eff(four_tiers()).principals
    assert (p.identity_id, p.tier, p.hops) == ("prod_role", JIT, 1)


def test_a_path_is_as_hard_as_its_weakest_link():
    """A standing hop onto a role whose own grant is time-bound: TEMPORARY."""
    graph = graph_of(
        person("a"), role("r"), res("r_res", principal_id="r"), res("db"),
        grant("g_a", "a", "r_res", "impersonate"),
        grant("g_r", "r", "db", "admin", lifecycle="time_bound", expires_at=iso(days=5)),
    )
    r = eff(graph, "a")
    assert r.get("r_res", Capability.IMPERSONATE).tier is STANDING
    assert r.get("db", A).tier is TEMPORARY


def test_tier_beats_hop_count():
    """
    db is two hops away through a JIT role and three hops away through standing
    ones. The standing route is kept: it needs nobody's approval.
    """
    graph = graph_of(
        person("a"), role("jr"), role("s1"), role("s2"),
        res("jr_res", principal_id="jr"), res("s1_res", principal_id="s1"),
        res("s2_res", principal_id="s2"), res("db"),
        grant("g_jit", "a", "jr_res", "impersonate", **JIT_GRANT),
        grant("g_jr_db", "jr", "db"),
        grant("g_s1", "a", "s1_res", "impersonate"),
        grant("g_s1_s2", "s1", "s2_res", "impersonate"),
        grant("g_s2_db", "s2", "db"),
    )
    hit = eff(graph, "a").get("db", A)
    assert hit.tier is STANDING
    assert hit.hops == 3
    assert ids(hit.path) == [
        "g_s1", "becomes:s1_res", "g_s1_s2", "becomes:s2_res", "g_s2_db"
    ]


# --- Hop limit and input -----------------------------------------------------


def test_truncation_is_reported_per_tier():
    """Only the JIT walk has a second hop to take, so only it is cut short."""
    r = eff(four_tiers(), max_hops=1)
    assert r.truncated == (JIT,)
    assert r.get("prod", A) is None
    assert eff(four_tiers(), max_hops=2).truncated == ()


def test_naive_evaluation_time_is_rejected():
    with pytest.raises(ValueError):
        effective_reach(four_tiers(), "bob", at=ANCHOR.replace(tzinfo=None), max_hops=2)


def test_is_deterministic():
    assert eff(four_tiers()) == eff(four_tiers())


# --- The whole corpus ----------------------------------------------------------


def corpus():
    estate = Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    return estate, IdentityGraph.from_estate(estate)


def test_widest_tier_is_exactly_reach_over_any_grant():
    estate, graph = corpus()
    for identity in estate.identities:
        tiered = eff(graph, identity.id)
        plain = reach(graph, identity.id, max_hops=4, usable=any_grant)
        assert {(e.resource_id, e.capability) for e in tiered.at_most(JIT)} == {
            (r.resource_id, r.capability) for r in plain.resources
        }


def test_irenes_role_is_only_reachable_through_jit():
    """Her impersonate grant on the finance admin role is JIT-eligible."""
    _, graph = corpus()
    r = eff(graph, "irene")
    assert r.get("finance_admin_role", Capability.IMPERSONATE).tier is JIT
    assert r.get("sso_portal", Capability.AUTHENTICATE).tier is STANDING
