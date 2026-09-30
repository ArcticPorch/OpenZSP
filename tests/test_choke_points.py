"""
Choke points: single links whose removal cuts the most routes to crown jewels,
with every cut verified by walking again without the link.
"""

import pytest

from app.connectors.synthetic import SyntheticConnector
from app.graph.graph import EdgeKind
from app.normalize.normalizer import Normalizer
from app.risk import detections
from app.risk.choke_points import find_choke_points
from tests.test_normalize import ANCHOR, normalize
from tests.test_reach import grant, person, res, role


def report(*records):
    estate = normalize(records)
    assert estate.issues == ()
    return find_choke_points(estate, ANCHOR)


def cuts(rep):
    return {p.edge_id: len(p.cuts) for p in rep.choke_points}


def shared_role(n=3):
    """n contractors can each step into one role that administers a crown jewel."""
    return report(
        *[person(f"c{i}") for i in range(n)],
        role("r"), res("r_res", sensitivity="medium", principal_id="r"), res("jewel"),
        *[grant(f"g_c{i}", f"c{i}", "r_res", "impersonate") for i in range(n)],
        grant("g_r", "r", "jewel"),
    )


def test_the_shared_link_ranks_first():
    rep = shared_role(3)
    assert [r.pair for r in rep.routes] == [("c0", "jewel"), ("c1", "jewel"), ("c2", "jewel")]
    assert [p.edge_id for p in rep.choke_points[:2]] == ["becomes:r_res", "g_r"]
    assert cuts(rep) == {"becomes:r_res": 3, "g_r": 3, "g_c0": 1, "g_c1": 1, "g_c2": 1}
    assert rep.choke_points[0].kind is EdgeKind.BECOMES
    assert rep.uncut == ()


def test_a_link_with_a_bypass_is_not_a_choke_point():
    """Two independent roles to the same jewel: no single link closes it."""
    rep = report(
        person("a"), role("r1"), role("r2"),
        res("r1_res", sensitivity="medium", principal_id="r1"),
        res("r2_res", sensitivity="medium", principal_id="r2"), res("jewel"),
        grant("g_a1", "a", "r1_res", "impersonate"), grant("g_a2", "a", "r2_res", "impersonate"),
        grant("g_1", "r1", "jewel"), grant("g_2", "r2", "jewel"),
    )
    assert [r.pair for r in rep.routes] == [("a", "jewel")]
    assert rep.choke_points == ()
    assert rep.uncut == (("a", "jewel"),)


def short_and_long_route():
    """a reaches the jewel in 2 hops through r0, and in 4 hops through r1 -> r2 -> r3."""
    return normalize([
        person("a"), *[role(f"r{i}") for i in range(4)],
        *[res(f"r{i}_res", sensitivity="medium", principal_id=f"r{i}") for i in range(4)],
        res("jewel"),
        grant("g_short", "a", "r0_res", "impersonate"), grant("g_r0", "r0", "jewel"),
        grant("g_long", "a", "r1_res", "impersonate"),
        grant("g_12", "r1", "r2_res", "impersonate"), grant("g_23", "r2", "r3_res", "impersonate"),
        grant("g_3j", "r3", "jewel"),
    ])


def test_a_bypass_counts_only_within_the_hop_limit(monkeypatch):
    """A route too long to be an attack path is no bypass."""
    assert find_choke_points(short_and_long_route(), ANCHOR).uncut == (("a", "jewel"),)

    monkeypatch.setattr(detections, "ATTACK_PATH_MAX_HOPS", 3)
    tighter = find_choke_points(short_and_long_route(), ANCHOR)
    assert tighter.uncut == ()
    assert "g_short" in cuts(tighter)


def test_governs_routes_are_included():
    """Detection reports gustav's route under permission management; remediation needs it too."""
    rep = report(
        person("gus"), res("tool", sensitivity="medium", governs=["ledger"]), res("ledger"),
        grant("g_tool", "gus", "tool", "manage_permission"),
    )
    assert [r.pair for r in rep.routes] == [("gus", "ledger")]
    assert cuts(rep) == {"g_tool": 1, "governs:tool>ledger": 1}


def test_jit_routes_and_direct_holdings_are_not_routes():
    rep = report(
        person("a"), person("b"), role("r"),
        res("r_res", sensitivity="medium", principal_id="r"), res("jewel"),
        grant("g_a", "a", "r_res", "impersonate", lifecycle="jit_eligible"),
        grant("g_b_direct", "b", "jewel"),
        grant("g_r", "r", "jewel"),
    )
    assert rep.routes == ()
    assert rep.choke_points == ()


def test_roles_are_not_origins():
    rep = shared_role(1)
    assert {r.origin for r in rep.routes} == {"c0"}


def test_naive_time_is_rejected():
    with pytest.raises(ValueError):
        find_choke_points(normalize([person("a")]), ANCHOR.replace(tzinfo=None))


def test_corpus_choke_points_are_deterministic():
    estate = Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    first = find_choke_points(estate, ANCHOR)
    assert first == find_choke_points(estate, ANCHOR)
    assert {r.pair for r in first.routes} == {
        ("gustav", "treasury_payments_ledger"),
        ("petra", "support_crm_db"),
    }
    assert "g_role_helpdesk_tier2_admin" in {p.edge_id for p in first.choke_points}
