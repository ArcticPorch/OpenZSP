"""
Cold-start grace (bulk_read_burst.v2): an identity too new to have a history
is not judged against one. The finding is kept, suppressed as a coverage gap.
"""

from datetime import timedelta

from app.risk.detections import BulkReadBurst
from app.risk.engine import RiskEngine
from tests.test_normalize import ANCHOR, event_ev, normalize
from tests.test_reach import grant, person, res

RULE = BulkReadBurst()


def reads(who, resource, n, start_days_ago, tag):
    start = ANCHOR - timedelta(days=start_days_ago)
    return [
        event_ev(f"e_{tag}_{i}", who, resource, payload={"action": "read", "success": True},
                 observed_at=start + timedelta(seconds=30 * i))
        for i in range(n)
    ]


def result(*records, who="a"):
    estate = normalize(list(records))
    return {r.identity_id: r for r in RiskEngine(rules=[RULE]).assess_estate(estate, ANCHOR)}[who]


def holder(granted_days_ago):
    return [person("a"), res("db", sensitivity="high"),
            grant("g", "a", "db", "read",
                  granted_at=(ANCHOR - timedelta(days=granted_days_ago)).isoformat())]


def test_a_brand_new_identity_is_suppressed_not_reported():
    r = result(*holder(3), *reads("a", "db", 200, 2, "burst"))
    assert r.assessment.triggered_factors == ()
    [held] = r.suppressed
    assert "too new to have a baseline" in held.description


def test_an_established_identity_is_judged_as_before():
    r = result(*holder(400), *reads("a", "db", 200, 2, "burst"))
    assert r.assessment.triggered_factors and not r.suppressed


def test_a_dormant_old_account_gets_no_grace():
    """Age counts from the oldest grant, so silence does not make an account 'new'."""
    r = result(*holder(400), *reads("a", "db", 200, 1, "burst"))
    assert r.assessment.triggered_factors
    assert "too new" not in r.assessment.triggered_factors[0].description
