"""
abandoned_grant.v1: a standing grant used, then left behind, judged against
the grant's own rhythm -- the shape FRESH v3's amara exposed.
"""

from datetime import timedelta

from app.connectors.synthetic import SyntheticConnector
from app.normalize.normalizer import Normalizer
from app.risk.detections import AbandonedGrant
from app.risk.engine import RiskEngine
from tests.test_normalize import ANCHOR, event_ev, identity_ev, normalize
from tests.test_reach import grant, person, res

RULE = AbandonedGrant()


def uses(who, resource, action, days_ago, tag="u"):
    return [
        event_ev(f"e_{tag}_{d}", who, resource, payload={"action": action, "success": True},
                 observed_at=ANCHOR - timedelta(days=d))
        for d in days_ago
    ]


def finding(*records, who="a"):
    estate = normalize(list(records))
    result = {r.identity_id: r for r in RiskEngine(rules=[RULE]).assess_estate(estate, ANCHOR)}[who]
    found = result.assessment.triggered_factors + result.suppressed
    return found[0] if found else None


def holder(action="write", **grant_payload):
    return [person("a"), res("db", sensitivity="high"),
            grant("g", "a", "db", action, granted_at=(ANCHOR - timedelta(days=900)).isoformat(),
                  **grant_payload)]


def test_weekly_grant_abandoned_months_ago_fires():
    f = finding(*holder(), *uses("a", "db", "write", range(200, 560, 7)))
    assert f is not None
    assert "last used 200 days ago (threshold for this grant: 90)" in f.description


def test_a_quarterly_grant_is_judged_by_its_quarter():
    """The rhythm only raises the floor: 1.25 x 91 days is about 114."""
    quarterly = range(75, 800, 91)
    assert finding(*holder(), *uses("a", "db", "write", quarterly)) is None
    late = range(130, 800, 91)
    f = finding(*holder(), *uses("a", "db", "write", late))
    assert f is not None and "threshold for this grant: 114" in f.description


def test_a_grant_used_once_is_judged_by_the_floor():
    assert finding(*holder(), *uses("a", "db", "write", [120])) is not None
    assert finding(*holder(), *uses("a", "db", "write", [60])) is None


def test_a_never_used_grant_is_not_this_rule():
    """unused_standing_grant owns grants with no history at all."""
    assert finding(*holder(), *uses("a", "other", "write", [1])) is None


def test_only_events_the_grant_authorises_count_as_use():
    """Reading does not exercise a destroy grant -- so a destroy grant 'used' only by reads has no history."""
    assert finding(*holder("destroy"), *uses("a", "db", "read", range(200, 560, 7))) is None
    assert finding(*holder("destroy"), *uses("a", "db", "delete", range(200, 560, 7))) is not None


def test_a_recent_login_keeps_the_grant_alive():
    records = [*holder(), *uses("a", "db", "write", range(200, 560, 7)),
               *uses("a", "db", "login", [3], tag="l")]
    assert finding(*records) is None


def test_jit_grants_and_break_glass_are_skipped():
    old_use = uses("a", "db", "write", range(200, 560, 7))
    assert finding(*holder(lifecycle="jit_eligible"), *old_use) is None
    glass = [identity_ev("a", payload={"is_break_glass": True}), *holder()[1:], *old_use]
    assert finding(*glass) is None


def test_the_corpus_pair():
    estate = Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    results = {r.identity_id: r for r in RiskEngine(rules=[RULE]).assess_estate(estate, ANCHOR)}
    assert results["marisol"].assessment.triggered_factors
    assert not results["nikolai"].assessment.triggered_factors
