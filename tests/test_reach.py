"""
Reachability: what an identity can get to, within a hop limit, and how.
"""

from datetime import timedelta

import pytest

from app.connectors.synthetic import SyntheticConnector
from app.graph.graph import IdentityGraph
from app.graph.reach import active_at, any_grant, reach, standing_only
from app.graph.semantics import ALL_CAPABILITIES, effective_capabilities
from app.models.capability import Capability
from app.normalize.normalizer import Normalizer
from tests.test_normalize import ANCHOR, grant_ev, identity_ev, normalize, resource_ev

A = Capability.ADMIN


def graph_of(*records) -> IdentityGraph:
    estate = normalize(records)
    assert estate.issues == ()
    return IdentityGraph.from_estate(estate)


def person(pid):
    return identity_ev(pid)


def role(rid):
    return identity_ev(rid, payload={"identity_type": "role"})


def res(rid, **payload):
    return resource_ev(rid, payload=payload)


def grant(gid, who, what, action="admin", **payload):
    return grant_ev(gid, who, what, payload={"action": action, **payload})


def ids(path):
    return [e.edge_id for e in path]


def role_chain(irene_lifecycle="standing"):
    """irene -impersonate-> role resource =becomes=> role -admin-> ledger."""
    extra = {}
    if irene_lifecycle == "jit_eligible":
        extra = {"lifecycle": "jit_eligible"}
    return graph_of(
        person("irene"),
        role("role_fin"),
        res("fin_role_res", principal_id="role_fin"),
        res("ledger"),
        grant("g_irene", "irene", "fin_role_res", "impersonate", **extra),
        grant("g_role", "role_fin", "ledger"),
    )


# --- The basic walk --------------------------------------------------------


def test_direct_grant_is_one_hop():
    graph = graph_of(person("a"), res("db"), grant("g", "a", "db", "read"))
    r = reach(graph, "a", max_hops=3, usable=any_grant)
    [hit] = r.resources
    assert (hit.resource_id, hit.capability, hit.hops) == ("db", Capability.READ, 1)
    assert ids(hit.path) == ["g"]
    assert r.principals == () and not r.truncated


def test_stepping_through_a_role_costs_two_hops():
    """The becomes edge is on the path, for the explanation, but costs nothing."""
    r = reach(role_chain(), "irene", max_hops=3, usable=any_grant)
    ledger = r.get("ledger", A)
    assert ledger.hops == 2
    assert ids(ledger.path) == ["g_irene", "becomes:fin_role_res", "g_role"]
    [role_step] = r.principals
    assert (role_step.identity_id, role_step.hops) == ("role_fin", 1)


def test_manager_effectively_holds_everything_it_reaches():
    r = reach(role_chain(), "irene", max_hops=3, usable=any_grant)
    assert {x.capability for x in r.resources if x.resource_id == "ledger"} == ALL_CAPABILITIES
    assert {x.capability for x in r.resources if x.resource_id == "fin_role_res"} == {
        Capability.IMPERSONATE
    }


def test_reading_a_role_resource_does_not_step_into_the_role():
    graph = graph_of(
        person("a"), role("r"), res("r_res", principal_id="r"), res("db"),
        grant("g_read", "a", "r_res", "read"), grant("g_role", "r", "db"),
    )
    r = reach(graph, "a", max_hops=5, usable=any_grant)
    assert r.resource_ids() == ("r_res",)
    assert r.principals == ()


# --- Hop limit -------------------------------------------------------------


def test_hop_limit_stops_the_walk_and_says_so():
    short = reach(role_chain(), "irene", max_hops=1, usable=any_grant)
    assert short.resource_ids() == ("fin_role_res",)
    assert short.truncated  # the role's own grant was left unexplored

    enough = reach(role_chain(), "irene", max_hops=2, usable=any_grant)
    assert "ledger" in enough.resource_ids()
    assert not enough.truncated


def test_zero_hops_reaches_nothing():
    r = reach(role_chain(), "irene", max_hops=0, usable=any_grant)
    assert r.resources == () and r.truncated


@pytest.mark.parametrize("bad, exc", [(-1, ValueError), (1.5, TypeError), (True, TypeError)])
def test_hop_limit_must_be_a_non_negative_int(bad, exc):
    with pytest.raises(exc):
        reach(role_chain(), "irene", max_hops=bad, usable=any_grant)


# --- Which grants count ----------------------------------------------------


def test_jit_hop_counts_only_when_the_caller_says_so():
    graph = role_chain(irene_lifecycle="jit_eligible")
    assert reach(graph, "irene", max_hops=3, usable=standing_only).resources == ()
    assert "ledger" in reach(graph, "irene", max_hops=3, usable=any_grant).resource_ids()
    assert reach(graph, "irene", max_hops=3, usable=active_at(ANCHOR)).resources == ()


def test_active_at_skips_expired_and_keeps_elevated():
    window = {"granted_at": (ANCHOR - timedelta(hours=1)).isoformat()}
    graph = graph_of(
        person("a"), res("old"), res("now"),
        grant("g_old", "a", "old", lifecycle="time_bound",
              expires_at=(ANCHOR - timedelta(days=1)).isoformat()),
        grant("g_now", "a", "now", lifecycle="elevated",
              expires_at=(ANCHOR + timedelta(hours=3)).isoformat(), **window),
    )
    assert reach(graph, "a", max_hops=1, usable=active_at(ANCHOR)).resource_ids() == ("now",)
    assert reach(graph, "a", max_hops=1, usable=any_grant).resource_ids() == ("now", "old")


# --- Control planes --------------------------------------------------------


def governed():
    """gustav's shape: manage_permission on a MEDIUM tool that governs a ledger."""
    return graph_of(
        person("gus"), res("tool", governs=["ledger"]), res("ledger"),
        grant("g_tool", "gus", "tool", "manage_permission"),
    )


def test_permission_management_spreads_to_what_it_governs():
    r = reach(governed(), "gus", max_hops=2, usable=any_grant)
    ledger = r.get("ledger", A)
    assert ledger.hops == 2
    assert ids(ledger.path) == ["g_tool", "governs:tool>ledger"]


def test_governs_needs_a_managing_capability():
    graph = graph_of(
        person("gus"), res("tool", governs=["ledger"]), res("ledger"),
        grant("g_tool", "gus", "tool", "write"),
    )
    assert reach(graph, "gus", max_hops=5, usable=any_grant).resource_ids() == ("tool",)


def test_governing_a_role_resource_is_enough_to_become_the_role():
    """No grant on the role anywhere: rewriting its trust policy gets you in."""
    graph = graph_of(
        person("gus"), role("r"), res("tool", governs=["r_res"]),
        res("r_res", principal_id="r"), res("db"),
        grant("g_tool", "gus", "tool", "manage_permission"), grant("g_r", "r", "db"),
    )
    r = reach(graph, "gus", max_hops=3, usable=any_grant)
    assert ids(r.get("db", A).path) == [
        "g_tool", "governs:tool>r_res", "becomes:r_res", "g_r"
    ]
    assert r.get("db", A).hops == 3


# --- Paths -----------------------------------------------------------------


def test_the_shortest_route_wins():
    """a reaches db directly through r2 (2 hops) and via r1 -> r2 (3 hops)."""
    graph = graph_of(
        person("a"), role("r1"), role("r2"),
        res("r1_res", principal_id="r1"), res("r2_res", principal_id="r2"), res("db"),
        grant("g_a_r1", "a", "r1_res", "impersonate"),
        grant("g_a_r2", "a", "r2_res", "impersonate"),
        grant("g_r1_r2", "r1", "r2_res", "impersonate"),
        grant("g_r2_db", "r2", "db", "read"),
    )
    r = reach(graph, "a", max_hops=5, usable=any_grant)
    assert ids(r.get("db", Capability.READ).path) == ["g_a_r2", "becomes:r2_res", "g_r2_db"]


def test_cycles_terminate():
    """Two roles that can each assume the other."""
    graph = graph_of(
        person("a"), role("r1"), role("r2"),
        res("r1_res", principal_id="r1"), res("r2_res", principal_id="r2"),
        grant("g_a", "a", "r1_res", "impersonate"),
        grant("g_12", "r1", "r2_res", "impersonate"),
        grant("g_21", "r2", "r1_res", "impersonate"),
    )
    r = reach(graph, "a", max_hops=50, usable=any_grant)
    assert [p.identity_id for p in r.principals] == ["r1", "r2"]
    assert r.resource_ids() == ("r1_res", "r2_res")
    assert not r.truncated  # the walk ran out of new ground, not of hops


def test_equal_length_ties_break_the_same_way_every_run():
    graph = graph_of(
        person("a"), role("r1"), role("r2"),
        res("r1_res", principal_id="r1"), res("r2_res", principal_id="r2"), res("db"),
        grant("g_a1", "a", "r1_res", "impersonate"), grant("g_a2", "a", "r2_res", "impersonate"),
        grant("g_1", "r1", "db", "read"), grant("g_2", "r2", "db", "read"),
    )
    first = reach(graph, "a", max_hops=3, usable=any_grant)
    assert ids(first.get("db", Capability.READ).path)[0] == "g_a1"
    assert reach(graph, "a", max_hops=3, usable=any_grant) == first


def test_unknown_resources_are_still_reached():
    """Understating reach is the direction we must not err in."""
    graph = IdentityGraph.from_estate(normalize([person("a"), grant("g", "a", "ghost")]))
    assert reach(graph, "a", max_hops=1, usable=any_grant).resource_ids() == ("ghost",)


# --- The whole corpus ------------------------------------------------------


def test_one_hop_reach_is_exactly_the_direct_grants():
    """With no second hop, reach must agree with what each identity holds."""
    estate = Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    graph = IdentityGraph.from_estate(estate)
    for identity in estate.identities:
        expected = {
            (p.resource_id, cap)
            for p in identity.permissions
            for cap in effective_capabilities(p.action)
        }
        got = reach(graph, identity.id, max_hops=1, usable=any_grant)
        assert {(r.resource_id, r.capability) for r in got.resources} == expected
