"""
Rules that read effective reach, and the engine wiring that gives it to them.

* `standing_permission_management.v2` -- a standing path whose last grant is
  explicit permission management, ending on a HIGH+ resource.
* `standing_blast_radius.v2` -- breadth (resources in standing reach) gated on
  depth (a CRITICAL among them); the score scales impact.
* `attack_path_to_crown_jewel.v1` -- control of a CRITICAL resource held only
  through an indirect live path, minus what permission management v2 reports.
"""

from datetime import timedelta

import pytest

from app.evidence.models import RecordKind
from app.graph.effective import effective_reach
from app.graph.graph import IdentityGraph
from app.risk import calibration, detections, scoring
from app.risk.coverage import CoverageAnalyzer
from app.risk.detections import (
    AttackPathToCrownJewel,
    StandingBlastRadius,
    StandingPermissionManagement,
)
from app.risk.engine import RiskEngine
from app.risk.features import FeatureExtractor
from app.risk.rules import RuleContext
from tests.test_normalize import ANCHOR, identity_ev, normalize
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


def test_walk_bound_lower_edge_on_train():
    """
    REACH_MAX_HOPS is a compute bound, not a detection threshold: it needs only
    a lower edge. gustav's ledger is two hops away; vesna's six. Every value
    from six up gets TRAIN right, and the bound sits above that.
    """
    one, five, six = calibration.sweep("REACH_MAX_HOPS", [1, 5, 6], ANCHOR)
    assert "gustav/EXCESSIVE_PRIVILEGE" in one.false_negatives
    assert "vesna/PRIVILEGE_ESCALATION" in five.false_negatives
    assert six.perfect
    assert detections.REACH_MAX_HOPS >= 6


# --- standing_blast_radius.v2 --------------------------------------------------

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
    """One direct grant: v1 counted 1. Reach counts the four systems behind the role."""
    f = blast_finding(wide_role(), "x")
    assert f is not None
    assert f.description.startswith("4 resources in standing reach, 1 CRITICAL")


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
    # jewel admin 30, three MEDIUM writes 1.5 each; the role resource is a stepping-stone
    score = 30.0 + 3 * 1.5
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


# --- attack_path_to_crown_jewel.v1 ---------------------------------------------

PATH = AttackPathToCrownJewel()


def path_finding(estate, who):
    result = {r.identity_id: r for r in RiskEngine(rules=[PATH]).assess_estate(estate, ANCHOR)}[who]
    found = result.assessment.triggered_factors + result.suppressed
    return found[0] if found else None


def chain(first=None, last="admin", crown=None, external=False, extra=()):
    """x -impersonate-> r_res =becomes=> r -<last>-> jewel."""
    return est(
        identity_ev("x", payload={"is_external": external}),
        role("r"), res("r_res", sensitivity="medium", principal_id="r"),
        res("jewel", **(crown or {})),
        grant("g_x", "x", "r_res", "impersonate", **(first or {})),
        grant("g_r", "r", "jewel", last),
        *extra,
    )


def test_attack_path_is_reported_with_its_route():
    f = path_finding(chain(), "x")
    assert "x -impersonate-> r_res =becomes=> r -admin-> jewel" in f.description
    assert "in 2 hops (standing)" in f.description


def test_a_jit_first_hop_breaks_the_path():
    assert path_finding(chain(first={"lifecycle": "jit_eligible"}), "x") is None


def test_an_expired_but_attached_hop_still_counts():
    """A lingering expired grant usually means the revocation failed."""
    expired = {"lifecycle": "time_bound", "expires_at": (ANCHOR - timedelta(days=3)).isoformat()}
    f = path_finding(chain(first=expired), "x")
    assert f is not None and "(expired_attached)" in f.description


def test_only_crown_jewels_count():
    assert path_finding(chain(crown={"sensitivity": "high"}), "x") is None


def test_reading_a_database_is_not_control_but_reading_a_vault_is():
    assert path_finding(chain(last="read"), "x") is None
    vault = chain(last="read", crown={"resource_type": "secret_store"})
    assert path_finding(vault, "x") is not None


def test_targets_held_directly_belong_to_the_privilege_rules():
    direct = chain(extra=(grant("g_x_direct", "x", "jewel", "admin"),))
    assert path_finding(direct, "x") is None


def test_an_admin_is_still_reported_for_a_different_crown_jewel():
    """bob's case: direct admin on one jewel, a role path to another."""
    estate = chain(extra=(res("own_jewel"), grant("g_x_own", "x", "own_jewel", "admin")))
    f = path_finding(estate, "x")
    assert f is not None and "-admin-> jewel" in f.description and "own_jewel" not in f.description


def governs_path(**lifecycle):
    return est(
        person("x"), res("tool", sensitivity="medium", governs=["jewel"]), res("jewel"),
        grant("g_tool", "x", "tool", "manage_permission", **lifecycle),
    )


def test_standing_permission_management_paths_are_left_to_v2():
    """Same situation, one finding."""
    assert path_finding(governs_path(), "x") is None
    assert finding(governs_path(), "x") is not None  # standing_permission_management.v2


def test_a_temporary_permission_management_path_is_an_attack_path():
    """v2 only reports standing power, so this one is not double-counted."""
    temp = governs_path(lifecycle="time_bound", expires_at=(ANCHOR + timedelta(days=5)).isoformat())
    assert finding(temp, "x") is None
    f = path_finding(temp, "x")
    assert f is not None and "~governs~> jewel" in f.description


def test_external_origin_raises_likelihood():
    assert path_finding(chain(external=True), "x").likelihood > path_finding(chain(), "x").likelihood
    assert path_finding(chain(external=True), "x").description.startswith("External principal")


def test_the_finding_cites_every_hop():
    estate = chain()
    f = path_finding(estate, "x")
    assert f.evidence_ids == (
        estate.evidence_ids_for(RecordKind.PERMISSION_GRANT, "g_x")
        + estate.evidence_ids_for(RecordKind.RESOURCE, "r_res")
        + estate.evidence_ids_for(RecordKind.PERMISSION_GRANT, "g_r")
    )


def test_attack_path_declines_without_a_reach():
    estate = chain()
    x = estate.identity("x")
    ctx = RuleContext(
        identity=x,
        features=FeatureExtractor.extract_features(x, estate.resources, estate.events, ANCHOR),
        coverage=CoverageAnalyzer.summarize(x, estate.events, estate, ANCHOR),
        evaluation_time=ANCHOR,
        resources=estate.resources,
        index=estate,
    )
    assert not PATH.evaluate(ctx).fired


def test_attack_path_bound_lower_edge_on_train():
    """petra is two hops out, teodor three, vesna six: the bound must reach six."""
    one, five, six = calibration.sweep("ATTACK_PATH_MAX_HOPS", [1, 5, 6], ANCHOR)
    assert "petra/PRIVILEGE_ESCALATION" in one.false_negatives
    assert "vesna/PRIVILEGE_ESCALATION" in five.false_negatives
    assert "teodor/PRIVILEGE_ESCALATION" not in five.false_negatives
    assert six.perfect
    assert detections.ATTACK_PATH_MAX_HOPS >= 6


def test_likelihood_falls_with_every_hop_but_stays_a_finding():
    """A long chain is less certain, not harmless."""
    lik = [scoring.attack_path_likelihood(h, external=False) for h in (2, 3, 4, 6)]
    assert lik == pytest.approx([7.0, 6.3, 5.6, 4.2])
    assert scoring.attack_path_likelihood(2, external=True) == pytest.approx(8.5)
    assert scoring.attack_path_likelihood(50, external=False) == scoring.ATTACK_PATH_LIKELIHOOD_FLOOR
