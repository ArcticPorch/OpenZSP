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
