"""
Blast radius: sensitivity x exposure x capability, summed over reachable
resources, at three cuts (standing, live, potential).
"""

from datetime import timedelta

import pytest

from app.connectors.synthetic import SyntheticConnector
from app.graph.effective import effective_reach
from app.graph.graph import IdentityGraph
from app.models.capability import Capability
from app.models.resource import Sensitivity
from app.normalize.normalizer import Normalizer
from app.risk import scoring
from app.risk.blast_radius import LIVE, POTENTIAL, STANDING, blast_radius
from tests.test_normalize import ANCHOR, normalize
from tests.test_reach import grant, person, res, role


def br(*records, who="a", cut=STANDING):
    estate = normalize(records)
    reach = effective_reach(IdentityGraph.from_estate(estate), who, at=ANCHOR, max_hops=4)
    return blast_radius(reach, {r.id: r for r in estate.resources}, cut)


# --- One resource ------------------------------------------------------------


@pytest.mark.parametrize(
    "sensitivity, action, expected",
    [
        ("critical", "admin", 30.0),
        ("critical", "write", 15.0),
        ("critical", "read", 6.0),
        ("high", "destroy", 10.0),
        ("medium", "write", 1.5),
        ("low", "read", 0.2),
    ],
)
def test_weight_is_sensitivity_times_capability(sensitivity, action, expected):
    b = br(person("a"), res("r", sensitivity=sensitivity), grant("g", "a", "r", action))
    assert b.score == pytest.approx(expected)


def test_exposure_multiplies():
    internal = br(person("a"), res("r"), grant("g", "a", "r"))
    public = br(person("a"), res("r", exposure="public"), grant("g", "a", "r"))
    assert public.score == pytest.approx(internal.score * 1.5)


def test_reading_a_secret_store_is_privileged():
    """A secret is someone else's access."""
    vault = br(person("a"), res("v", resource_type="secret_store"), grant("g", "a", "v", "read"))
    db = br(person("a"), res("d"), grant("g", "a", "d", "read"))
    assert vault.score == pytest.approx(30.0)
    assert db.score == pytest.approx(6.0)


def test_each_resource_counts_once_at_its_worst_capability():
    b = br(
        person("a"), res("r"),
        grant("g_read", "a", "r", "read"), grant("g_admin", "a", "r", "admin"),
    )
    [c] = b.contributions
    assert (c.resource_id, c.capability, c.weight) == ("r", Capability.ADMIN, 30.0)


def test_weights_are_read_at_call_time(monkeypatch):
    """So a sweep can override them by name, like every other tunable."""
    monkeypatch.setitem(scoring.BLAST_SENSITIVITY_WEIGHT, Sensitivity.CRITICAL, 100.0)
    assert br(person("a"), res("r"), grant("g", "a", "r")).score == pytest.approx(100.0)


# --- Across the graph ----------------------------------------------------------


def test_reach_through_a_role_counts():
    """What a count of direct grants cannot see."""
    b = br(
        person("a"), role("r"), res("r_res", sensitivity="low", principal_id="r"), res("db"),
        grant("g_a", "a", "r_res", "impersonate"), grant("g_r", "r", "db"),
    )
    assert [c.resource_id for c in b.contributions] == ["db"]
    assert b.contributions[0].hops == 2
    assert b.score == pytest.approx(30.0)


def test_stepping_stones_are_listed_not_counted():
    """
    The role's resource is the door into the role; what the role reaches is
    already counted through its grants. Counting the door too made one long
    chain read as breadth (vesna, kai).
    """
    b = br(
        person("a"), role("r"), res("r_res", principal_id="r"), res("db"),
        grant("g_a", "a", "r_res", "admin"), grant("g_r", "r", "db", "read"),
    )
    assert b.stepping_stones == ("r_res",)
    assert [c.resource_id for c in b.contributions] == ["db"]


def test_breadth_adds_and_crown_jewels_dominate():
    wide_reads = br(person("a"), *[res(f"d{i}", sensitivity="low") for i in range(30)],
                    *[grant(f"g{i}", "a", f"d{i}", "read") for i in range(30)])
    one_jewel = br(person("a"), res("jewel"), grant("g", "a", "jewel"))
    assert wide_reads.score == pytest.approx(6.0)
    assert one_jewel.score == pytest.approx(30.0)


# --- Cuts ----------------------------------------------------------------------


def lifecycles():
    return (
        person("a"), res("always"), res("elevated"), res("expired"), res("jit"),
        grant("g_s", "a", "always"),
        grant("g_e", "a", "elevated", lifecycle="elevated",
              granted_at=(ANCHOR - timedelta(hours=1)).isoformat(),
              expires_at=(ANCHOR + timedelta(hours=3)).isoformat()),
        grant("g_x", "a", "expired", lifecycle="time_bound",
              expires_at=(ANCHOR - timedelta(days=9)).isoformat()),
        grant("g_j", "a", "jit", lifecycle="jit_eligible"),
    )


def test_three_cuts():
    ids = {cut: [c.resource_id for c in br(*lifecycles(), cut=cut).contributions]
           for cut in (STANDING, LIVE, POTENTIAL)}
    assert ids[STANDING] == ["always"]
    assert ids[LIVE] == ["always", "elevated", "expired"]  # a failed revocation still works
    assert ids[POTENTIAL] == ["always", "elevated", "expired", "jit"]


def test_the_cut_picks_the_capability_available_at_it():
    """Standing read, JIT admin: the standing score must not borrow the JIT admin."""
    records = (person("a"), res("r"), grant("g_read", "a", "r", "read"),
               grant("g_admin", "a", "r", "admin", lifecycle="jit_eligible"))
    assert br(*records, cut=STANDING).score == pytest.approx(6.0)
    assert br(*records, cut=POTENTIAL).score == pytest.approx(30.0)


def test_cut_must_be_a_tier():
    with pytest.raises(TypeError):
        br(person("a"), cut="standing")


# --- Unknowns and explanation --------------------------------------------------


def test_unknown_resources_are_listed_not_weighted():
    b = br(person("a"), res("r"), grant("g1", "a", "r"), grant("g2", "a", "ghost"))
    assert b.unknown_resources == ("ghost",)
    assert b.score == pytest.approx(30.0)


def test_unclassified_capabilities_are_listed_not_weighted():
    b = br(person("a"), res("r"), grant("g", "a", "r", "frobnicate"))
    assert b.unclassified_resources == ("r",)
    assert b.contributions == () and b.score == 0


def test_shares_explain_the_score():
    b = br(person("a"), res("jewel"), res("wiki", sensitivity="low"),
           grant("g1", "a", "jewel"), grant("g2", "a", "wiki", "read"))
    assert [c.resource_id for c in b.contributions] == ["jewel", "wiki"]  # heaviest first
    assert b.share("jewel") == pytest.approx(30.0 / 30.2)
    assert sum(b.share(c.resource_id) for c in b.contributions) == pytest.approx(1.0)
    assert b.max_sensitivity is Sensitivity.CRITICAL
    assert b.count_at(Sensitivity.LOW) == 1


def test_empty_reach_scores_zero():
    b = br(person("a"))
    assert b.score == 0 and b.share("x") == 0.0 and b.max_sensitivity is None


# --- The corpus ------------------------------------------------------------------


def test_sprawl_outweighs_the_read_only_analyst():
    """The pair that sank grant counting: six grants each, very different reach."""
    estate = Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    graph = IdentityGraph.from_estate(estate)
    resources = {r.id: r for r in estate.resources}

    def score(who):
        reach = effective_reach(graph, who, at=ANCHOR, max_hops=4)
        return blast_radius(reach, resources, STANDING).score

    assert score("svc_ci_runner") > 10 * score("iris")
