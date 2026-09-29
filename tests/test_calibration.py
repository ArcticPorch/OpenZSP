"""
The cross-identity baseline and the threshold-sweep tool.

Both exist to protect a discipline rather than to compute anything clever: the
baseline keeps rules O(1) while letting one of them compare across identities,
and the sweep makes tuning against a held-out split impossible rather than
merely discouraged.
"""

from datetime import datetime, timezone

import pytest

from app.connectors.synthetic import FRESH, HOLDOUT, TRAIN, SyntheticConnector
from app.models.identity import Identity, IdentityType
from app.models.permission import GrantLifecycle, Permission
from app.models.capability import Capability
from app.normalize.normalizer import Normalizer
from app.risk import calibration, detections
from app.risk.baselines import PeerBaseline
from app.risk.engine import RiskEngine
from app.risk.models import RiskFactorType

ANCHOR = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)


def person(pid: str, dept: str, *resources: str) -> Identity:
    return Identity(
        id=pid,
        name=pid,
        identity_type=IdentityType.HUMAN,
        department=dept,
        permissions=[
            Permission(
                id=f"g_{pid}_{r}",
                identity_id=pid,
                resource_id=r,
                action=Capability.READ,
                lifecycle=GrantLifecycle.STANDING,
            )
            for r in resources
        ],
    )


# --- PeerBaseline ----------------------------------------------------------


def test_baseline_excludes_the_identity_itself():
    b = PeerBaseline.build([person("a", "Finance", "ledger"), person("b", "Marketing", "ledger")])
    assert b.other_holders("ledger", "b") == (("a", "Finance"),)


def test_baseline_is_order_independent():
    people = [person("a", "Finance", "x"), person("b", "Sales", "x", "y")]
    assert PeerBaseline.build(people) == PeerBaseline.build(list(reversed(people)))


def test_baseline_unknown_resource_has_no_holders():
    assert PeerBaseline.build([]).other_holders("nothing", "a") == ()


def test_peer_rule_declines_without_a_baseline():
    """A single-identity assessment has no peers; the rule must decline, not guess."""
    est = Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    result = RiskEngine().assess_identity(
        est.identity("oscar"), est.resources, est.events, est, ANCHOR
    )
    kinds = {f.factor_type for f in result.assessment.triggered_factors}
    assert RiskFactorType.CONTEXT_MISMATCH not in kinds


def test_peer_rule_fires_with_the_estate_baseline():
    est = Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    results = {r.identity_id: r for r in RiskEngine().assess_estate(est, ANCHOR)}
    kinds = {f.factor_type for f in results["oscar"].assessment.triggered_factors}
    assert RiskFactorType.CONTEXT_MISMATCH in kinds


# --- Sweeps ----------------------------------------------------------------


@pytest.mark.parametrize("split", [HOLDOUT, FRESH])
def test_sweep_refuses_held_out_splits(split):
    with pytest.raises(ValueError, match="TRAIN only"):
        calibration.sweep("CADENCE_TOLERANCE", [1.0], ANCHOR, split=split)


def test_sweep_rejects_unknown_names():
    with pytest.raises(ValueError):
        calibration.sweep("NOT_A_THRESHOLD", [1], ANCHOR)


def test_sweep_restores_the_original_value():
    before = detections.CADENCE_TOLERANCE
    calibration.sweep("CADENCE_TOLERANCE", [0.1, 9.0], ANCHOR)
    assert detections.CADENCE_TOLERANCE == before


def test_sweep_finds_both_edges_of_the_cadence_plateau():
    """0.5 fires on the semiannual job; 2.0 misses the stopped quarterly job."""
    points = calibration.sweep("CADENCE_TOLERANCE", [0.5, 1.25, 2.0], ANCHOR)
    low, mid, high = points
    assert "svc_semiannual_audit/STALE_ACCESS" in low.false_positives
    assert mid.perfect
    assert "svc_quarterly_recon/STALE_ACCESS" in high.false_negatives


def test_plateau_picks_the_widest_run():
    def pt(v, ok):
        return calibration.SweepPoint(v, 1, 1, 1, () if ok else ("x",), (), 0)

    points = [pt(1, True), pt(2, False), pt(3, True), pt(4, True), pt(5, True), pt(6, False)]
    assert calibration.plateau(points) == (3, 5)
    assert calibration.plateau([pt(1, False)]) is None


def test_structural_misses_do_not_hide_the_plateau():
    """No threshold can move them, so they must not make every value imperfect."""
    [structural] = sorted(calibration.STRUCTURAL_MISSES)[:1]
    only_structural = calibration.SweepPoint(1, 1, 1, 1, (), (structural,), 0)
    assert only_structural.perfect and only_structural.errors == 0
    tunable = calibration.SweepPoint(1, 1, 1, 1, (), (structural, "x/STALE_ACCESS"), 0)
    assert not tunable.perfect and tunable.errors == 1


def test_calibrated_value_sits_inside_the_train_plateau():
    """
    Cycle 1 set 1.25 as the midpoint of (120/182, 160/91). Cycle 2's key-rotation
    trap (150 days idle on a 180-day rhythm) raised the lower edge to 150/180;
    1.25 is still comfortably inside, so it was kept.
    """
    assert detections.CADENCE_TOLERANCE == 1.25
    assert 150 / 180 < detections.CADENCE_TOLERANCE < 160 / 91


def test_tuning_curves_render_a_self_contained_svg():
    from app.risk.curves import Curve, render_svg

    svg = render_svg(ANCHOR, curves=(Curve("MIN_CADENCE_GAPS", (1, 2, 3), previous=3),))
    assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
    assert "prefers-color-scheme: dark" in svg  # dark mode is selected, not flipped
    assert "MIN_CADENCE_GAPS" in svg and "all correct: only at 2" in svg
    assert "http" not in svg.replace("http://www.w3.org/2000/svg", "")  # no external assets


def test_cycle_two_values_are_the_only_or_middle_all_correct_ones():
    """
    Cycle 2: MIN_CADENCE_GAPS has exactly one all-correct value; the peer
    share sits mid-way through [0, 0.2). Pinned so a later edit has to
    re-run the sweep rather than drift.
    """
    gaps = calibration.sweep("MIN_CADENCE_GAPS", [1, 2, 3], ANCHOR)
    assert [p.perfect for p in gaps] == [False, True, False]
    assert detections.MIN_CADENCE_GAPS == 2

    share = calibration.sweep("PEER_MAX_SAME_DEPT_SHARE", [0.0, 0.1, 0.19, 0.2], ANCHOR)
    assert [p.perfect for p in share] == [True, True, True, False]
    assert detections.PEER_MAX_SAME_DEPT_SHARE == 0.1
