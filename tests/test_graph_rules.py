"""
Rules that read effective reach, and the engine wiring that gives it to them.

`standing_permission_management.v2` extends v1 along the graph: it fires on a
standing path whose last grant is explicit permission management and which
ends on a HIGH+ resource -- directly, through a `governs` hop, or through a
role stepped into on the way.
"""

import pytest

from app.evidence.models import RecordKind
from app.graph.effective import effective_reach
from app.graph.graph import IdentityGraph
from app.risk import calibration, detections
from app.risk.coverage import CoverageAnalyzer
from app.risk.detections import StandingPermissionManagement
from app.risk.engine import RiskEngine
from app.risk.features import FeatureExtractor
from app.risk.rules import RuleContext
from tests.test_normalize import ANCHOR, normalize
from tests.test_reach import grant, person, res, role

RULE = StandingPermissionManagement()


def finding(estate, who, *, whole_estate=True):
    """This rule's finding on `who`, reported or suppressed, else None."""
    engine = RiskEngine(rules=[RULE])
    if whole_estate:
        results = {r.identity_id: r for r in engine.assess_estate(estate, ANCHOR)}
        result = results[who]
    else:
        result = engine.assess_identity(
            estate.identity(who), estate.resources, estate.events, estate, ANCHOR
        )
    found = result.assessment.triggered_factors + result.suppressed
    return found[0] if found else None


def est(*records):
    estate = normalize(records)
    assert estate.issues == ()
    return estate


def via_role(last_action="manage_permission", sensitivity="critical", **first):
    """x -impersonate-> role resource => role -<last_action>-> db."""
    return est(
        person("x"), role("r"), res("r_res", principal_id="r"),
        res("db", sensitivity=sensitivity),
        grant("g_x", "x", "r_res", "impersonate", **first),
        grant("g_r", "r", "db", last_action),
    )


# --- What v2 fires on --------------------------------------------------------


def test_fires_on_permission_management_reached_through_a_role():
    f = finding(via_role(), "x")
    assert f is not None
    assert "indirectly (db)" in f.description


def test_the_finding_cites_every_hop():
    estate = via_role()
    f = finding(estate, "x")
    expected = (
        estate.evidence_ids_for(RecordKind.PERMISSION_GRANT, "g_x")
        + estate.evidence_ids_for(RecordKind.RESOURCE, "r_res")  # declares the role link
        + estate.evidence_ids_for(RecordKind.PERMISSION_GRANT, "g_r")
    )
    assert f.evidence_ids == expected


def test_admin_at_the_end_of_the_path_is_the_privilege_rules_job():
    """A manager's effective capabilities include manage_permission; admin's do too."""
    assert finding(via_role(last_action="admin"), "x") is None


def test_a_jit_hop_anywhere_is_not_standing_power():
    assert finding(via_role(lifecycle="jit_eligible"), "x") is None


def test_low_value_end_does_not_fire():
    assert finding(via_role(sensitivity="medium"), "x") is None


def test_manage_identity_still_counts():
    assert finding(via_role(last_action="manage_identity"), "x") is not None


def test_direct_grant_behaves_as_v1():
    estate = est(person("v"), res("plane"), grant("g_v", "v", "plane", "manage_permission"))
    f = finding(estate, "v")
    assert f is not None and "indirectly" not in f.description


# --- Wiring ---------------------------------------------------------------------


def test_declines_without_a_reach():
    estate = via_role()
    x = estate.identity("x")
    ctx = RuleContext(
        identity=x,
        features=FeatureExtractor.extract_features(x, estate.resources, estate.events, ANCHOR),
        coverage=CoverageAnalyzer.summarize(x, estate.events, estate, ANCHOR),
        evaluation_time=ANCHOR,
        resources=estate.resources,
        index=estate,
    )
    assert not RULE.evaluate(ctx).fired


def test_reach_must_belong_to_the_context_identity():
    estate = via_role()
    x = estate.identity("x")
    other = effective_reach(IdentityGraph.from_estate(estate), "r", at=ANCHOR, max_hops=2)
    with pytest.raises(ValueError, match="reach is for identity"):
        RuleContext(
            identity=x,
            features=FeatureExtractor.extract_features(x, estate.resources, (), ANCHOR),
            coverage=CoverageAnalyzer.summarize(x, (), estate, ANCHOR),
            evaluation_time=ANCHOR,
            reach=other,
        )


def test_single_identity_assessment_walks_what_it_honestly_can():
    """
    Without the estate, governs still resolves (it lives on resources) but a
    role cannot be stepped into (its grants are not there): narrower, not wrong.
    """
    governed = est(
        person("gus"), res("tool", sensitivity="medium", governs=["ledger"]), res("ledger"),
        grant("g_tool", "gus", "tool", "manage_permission"),
    )
    assert finding(governed, "gus", whole_estate=False) is not None
    assert finding(via_role(), "x", whole_estate=False) is None


# --- The corpus -------------------------------------------------------------------


def test_one_hop_limit_misses_gustav():
    """
    The hop limit's lower edge on TRAIN: gustav's ledger is two hops away.
    There is no upper edge yet -- REACH_MAX_HOPS is provisional until the
    graph scenarios bound it from above.
    """
    low, high = calibration.sweep("REACH_MAX_HOPS", [1, 2], ANCHOR)
    assert "gustav/EXCESSIVE_PRIVILEGE" in low.false_negatives
    assert high.perfect
    assert detections.REACH_MAX_HOPS >= 2


# --- standing_blast_radius.v2 --------------------------------------------------

from app.risk import scoring
from app.risk.detections import StandingBlastRadius

BLAST = StandingBlastRadius()


def blast_finding(estate, who):
    result = {r.identity_id: r for r in RiskEngine(rules=[BLAST]).assess_estate(estate, ANCHOR)}[who]
    found = result.assessment.triggered_factors + result.suppressed
    return found[0] if found else None


def wide_role(first=None, crown="critical"):
    """x holds ONE grant -- onto a role that reaches four resources, one of them `crown`."""
    first = first or {}
    return est(
        person("x"), role("r"), res("r_res", sensitivity="low", principal_id="r"),
        res("jewel", sensitivity=crown),
        *[res(f"svc{i}", sensitivity="medium") for i in range(3)],
        grant("g_x", "x", "r_res", "impersonate", **first),
        grant("g_jewel", "r", "jewel"),
        *[grant(f"g_svc{i}", "r", f"svc{i}", "write") for i in range(3)],
    )


def test_blast_radius_sees_breadth_behind_a_role():
    """One direct grant: v1 counted 1. Reach counts the role's five resources."""
    f = blast_finding(wide_role(), "x")
    assert f is not None
    assert f.description.startswith("5 resources in standing reach, 1 CRITICAL")


def test_blast_radius_ignores_a_jit_hop():
    assert blast_finding(wide_role(first={"lifecycle": "jit_eligible"}), "x") is None


def test_blast_radius_still_needs_a_crown_jewel():
    assert blast_finding(wide_role(crown="high"), "x") is None


def test_many_grants_on_one_resource_are_depth_not_breadth():
    estate = est(
        person("x"), res("db"),
        *[grant(f"g{i}", "x", "db", a) for i, a in enumerate(("read", "write", "destroy", "admin"))],
    )
    assert blast_finding(estate, "x") is None


def test_unclassified_reach_counts_as_breadth_but_not_score():
    """Not privileged, not harmless."""
    estate = est(
        person("x"), res("jewel"), *[res(f"v{i}", sensitivity="high") for i in range(3)],
        grant("g_j", "x", "jewel", "read"),
        *[grant(f"g_v{i}", "x", f"v{i}", "vendorx.opaque") for i in range(3)],
    )
    f = blast_finding(estate, "x")
    assert f is not None
    assert "3 unclassified" in f.description and "blast radius 6.0" in f.description


def test_impact_scales_with_the_score():
    f = blast_finding(wide_role(), "x")
    # jewel admin 30, three MEDIUM writes 1.5 each, impersonate (privileged) on the LOW role resource 1
    score = 30.0 + 3 * 1.5 + 1.0
    assert f.impact == pytest.approx(scoring.blast_impact(score))


def test_blast_impact_is_bounded_and_anchored():
    assert scoring.blast_impact(0.0) == 5.0
    assert scoring.blast_impact(30.0) == pytest.approx(7.5)  # one crown jewel's worth
    assert scoring.blast_impact(86.0) == pytest.approx(8.7, abs=0.05)
    assert scoring.blast_impact(1e9) < 10.0
    with pytest.raises(ValueError):
        scoring.blast_impact(-1.0)


def test_blast_radius_declines_without_a_reach():
    estate = wide_role()
    x = estate.identity("x")
    ctx = RuleContext(
        identity=x,
        features=FeatureExtractor.extract_features(x, estate.resources, estate.events, ANCHOR),
        coverage=CoverageAnalyzer.summarize(x, estate.events, estate, ANCHOR),
        evaluation_time=ANCHOR,
        resources=estate.resources,
        index=estate,
    )
    assert not BLAST.evaluate(ctx).fired
