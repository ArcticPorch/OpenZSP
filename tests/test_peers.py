"""
peer_access_outlier.v2: peers are holders of the same identity type, and
"your department" is your org family when the source supplies an org path.
"""

from app.risk.baselines import PeerBaseline
from app.risk.detections import PeerAccessOutlier
from app.risk.engine import RiskEngine
from tests.test_normalize import ANCHOR, identity_ev, normalize
from tests.test_reach import grant, res

RULE = PeerAccessOutlier()


def holder(pid, dept, kind="human", org_path=None):
    payload = {"department": dept, "identity_type": kind}
    if org_path:
        payload["org_path"] = org_path
    return [identity_ev(pid, payload=payload), grant(f"g_{pid}", pid, "ledger", "read")]


def fires(records, who):
    estate = normalize([res("ledger", sensitivity="high"), *records])
    result = {r.identity_id: r for r in RiskEngine(rules=[RULE]).assess_estate(estate, ANCHOR)}[who]
    return bool(result.assessment.triggered_factors or result.suppressed)


def clinical_team():
    return [r for i in range(4) for r in holder(f"ops{i}", "Trial Operations",
                                                 org_path="Clinical/Trial Operations")]


def test_an_adjacent_team_is_family_when_the_org_path_says_so():
    team = clinical_team()
    assert not fires(team + holder("x", "Biostatistics", org_path="Clinical/Biostatistics"), "x")
    # The same person with no org path is judged on the flat string, as v1 did.
    assert fires(team + holder("x", "Biostatistics"), "x")


def test_a_different_family_is_still_an_outlier():
    assert fires(clinical_team() + holder("x", "Brand", org_path="Commercial/Brand"), "x")


def test_a_service_is_compared_only_with_services():
    people = [r for i in range(4) for r in holder(f"fin{i}", "Finance")]
    assert not fires(people + holder("etl", "Data Engineering", kind="service"), "etl")
    services = [r for i in range(4) for r in holder(f"job{i}", "Billing Eng", kind="service")]
    assert fires(services + holder("bot", "Marketing", kind="service"), "bot")


def test_a_person_is_not_measured_against_service_accounts():
    """Four Billing-owned jobs on the ledger do not make a Finance analyst an outlier."""
    services = [r for i in range(4) for r in holder(f"job{i}", "Billing Eng", kind="service")]
    assert not fires(services + holder("ana", "Finance"), "ana")


def test_the_baseline_keeps_family_and_type():
    estate = normalize([res("ledger"), *holder("a", "Treasury", org_path="Finance/Treasury"),
                        *holder("b", "Marketing", kind="service")])
    peers = PeerBaseline.build(estate.identities)
    [other] = peers.others("ledger", "b")
    assert (other.identity_id, other.family, other.identity_type) == ("a", "Finance", "human")
    assert peers.other_holders("ledger", "b") == (("a", "Treasury"),)  # v1 view unchanged


def test_org_family_falls_back_to_the_department():
    estate = normalize([*holder("a", "Legal")])
    assert estate.identity("a").org_family == "Legal"
