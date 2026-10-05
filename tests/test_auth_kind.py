"""
Event.auth: how a sign-in happened, when the source can tell. Unknown is the
default and counts as interactive -- not knowing must never look safer.
"""

from datetime import timedelta

from app.models.event import AuthKind
from app.risk.detections import ServiceAccountInteractiveLogin
from app.risk.engine import RiskEngine
from tests.test_normalize import ANCHOR, event_ev, identity_ev, normalize, resource_ev
from tests.test_reach import grant

RULE = ServiceAccountInteractiveLogin()


def logins(auth=None, n=5):
    extra = {"auth": auth} if auth else {}
    return [event_ev(f"e{i}", "svc", "api", payload={"action": "login", "success": True, **extra},
                     observed_at=ANCHOR - timedelta(days=i + 1)) for i in range(n)]


def service_estate(*events):
    return normalize([identity_ev("svc", payload={"identity_type": "service"}),
                      resource_ev("api"), grant("g", "svc", "api", "write"), *events])


def finding(*events):
    [r] = RiskEngine(rules=[RULE]).assess_estate(service_estate(*events), ANCHOR)
    found = r.assessment.triggered_factors + r.suppressed
    return found[0] if found else None


def test_the_auth_kind_is_carried_and_defaults_to_unknown():
    est = service_estate(*logins("programmatic", 1))
    assert est.events[0].auth is AuthKind.PROGRAMMATIC
    assert service_estate(*logins(None, 1)).events[0].auth is AuthKind.UNKNOWN


def test_an_unrecognised_auth_kind_is_an_issue():
    est = service_estate(*logins("telepathy", 1))
    assert est.events == () and any("auth" in i.reason for i in est.issues)


def test_programmatic_logins_are_what_a_service_account_is_for():
    assert finding(*logins("programmatic")) is None


def test_interactive_logins_fire():
    assert finding(*logins("interactive")) is not None


def test_unknown_logins_still_count_and_say_so():
    f = finding(*logins(None))
    assert f is not None and "no auth kind recorded, counted as interactive" in f.description
