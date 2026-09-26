"""
The capability taxonomy, and the two bugs it exists to make impossible.

The regression tests here are the point of the whole refactor: permissions and
events now assert privilege against one set, so they cannot drift apart again,
and an action this taxonomy cannot classify is retained rather than dropped.
"""

from datetime import datetime, timezone

import pytest

from app.connectors.synthetic import SyntheticConnector
from app.models.capability import (
    PERMISSION_ALTERING_CAPABILITIES,
    PRIVILEGED_CAPABILITIES,
    Capability,
)
from app.models.event import EventAction
from app.models.permission import GrantLifecycle, Permission
from app.models.resource import Sensitivity
from app.normalize.normalizer import Normalizer
from app.risk.coverage import CoverageAnalyzer
from app.risk.detections import GRANT_EXERCISED_BY
from app.risk.engine import RiskEngine
from app.risk.scoring import MIN_REPORTING_CONFIDENCE, confidence_from_coverage

ANCHOR = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)


def estate():
    return Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())


# --- One vocabulary, one privilege set -------------------------------------


def test_every_event_action_maps_to_a_capability():
    for action in EventAction:
        assert isinstance(action.capability, Capability)


def test_destruction_is_privileged_on_both_sides():
    """
    Regression: DELETE was once a privileged event but not a privileged
    permission, so an identity holding standing delete on a crown jewel scored
    zero privileged permissions until it destroyed something.
    """
    assert Capability.DESTROY in PRIVILEGED_CAPABILITIES
    assert EventAction.DELETE.is_privileged
    assert EventAction.DELETE.capability is Capability.DESTROY


def test_permission_management_is_holdable_not_just_observable():
    """
    Regression: GRANT_PERMISSION / ASSUME_ROLE / REVOKE_PERMISSION were
    observable as events but had no PermissionAction counterpart, so the single
    most dangerous capability in an IAM system could not be modelled as held --
    only as already exercised.
    """
    for action in (
        EventAction.GRANT_PERMISSION,
        EventAction.REVOKE_PERMISSION,
        EventAction.ASSUME_ROLE,
    ):
        assert action.capability in PRIVILEGED_CAPABILITIES
        # The capability is expressible as a grant, which is the whole fix.
        perm = Permission(
            id="p",
            identity_id="i",
            resource_id="r",
            action=action.capability,
            lifecycle=GrantLifecycle.STANDING,
        )
        assert perm.action.is_privileged


def test_event_and_permission_privilege_cannot_disagree():
    """
    There is one set, so the two sides read the same source by construction.

    This is the structural guarantee: the old design had two hand-maintained
    sets and they drifted twice.
    """
    for action in EventAction:
        assert action.is_privileged == (action.capability in PRIVILEGED_CAPABILITIES)


def test_authenticate_is_not_privileged():
    """Being able to log in is the precondition for access, not an elevation."""
    assert Capability.AUTHENTICATE not in PRIVILEGED_CAPABILITIES
    assert not EventAction.LOGIN.is_privileged


def test_unknown_is_neither_privileged_nor_permission_altering():
    """
    An unclassified capability is a coverage problem, not a finding.

    Treating it as privileged would manufacture alerts out of our own
    ignorance; what actually happens to it is suppressed confidence.
    """
    assert Capability.UNKNOWN not in PRIVILEGED_CAPABILITIES
    assert Capability.UNKNOWN not in PERMISSION_ALTERING_CAPABILITIES


def test_every_capability_has_an_exercise_mapping():
    """A capability with no mapping would be reported unused forever."""
    assert set(GRANT_EXERCISED_BY) == set(Capability)


# --- Translating a provider's vocabulary -----------------------------------


@pytest.mark.parametrize(
    "token,expected",
    [
        ("admin", Capability.ADMIN),
        ("delete", Capability.DESTROY),
        ("login", Capability.AUTHENTICATE),
        ("assume_role", Capability.IMPERSONATE),
        ("grant_permission", Capability.MANAGE_PERMISSION),
        ("revoke_permission", Capability.MANAGE_PERMISSION),
        ("s3:DeleteObject", Capability.DESTROY),
        ("iam:AttachUserPolicy", Capability.MANAGE_PERMISSION),
        ("iam:CreateAccessKey", Capability.MANAGE_IDENTITY),
        ("cloudtrail:StopLogging", Capability.MANAGE_SECURITY_CONTROL),
        ("ec2:DescribeInstances", Capability.READ),
        ("dynamodb:PutItem", Capability.WRITE),
        ("  ADMIN  ", Capability.ADMIN),
    ],
)
def test_from_token_translates_provider_vocabularies(token, expected):
    assert Capability.from_token(token) is expected


@pytest.mark.parametrize("token", ["", "   ", "vendorx.superuser", None, 42, object()])
def test_from_token_never_raises_and_falls_back_to_unknown(token):
    assert Capability.from_token(token) is Capability.UNKNOWN


def test_from_token_is_idempotent():
    for cap in Capability:
        assert Capability.from_token(cap) is cap
        assert Capability.from_token(cap.value) is cap


# --- The retention fix -----------------------------------------------------


def test_unmapped_grants_are_retained_not_dropped():
    """
    The bug this closes: `_parse_enum` turned an unknown action into a
    NormalizationIssue, which dropped the grant.

    Understating access is the one direction a privilege engine must not err
    in, and a dropped grant understates it silently.
    """
    est = estate()
    yusuf = est.identity("yusuf")
    assert yusuf is not None
    assert len(yusuf.permissions) == 4
    assert sum(1 for p in yusuf.permissions if p.action is Capability.UNKNOWN) == 3
    assert est.issues == ()


def test_unknown_capabilities_suppress_confidence():
    """Retention alone would be worse than dropping: it must cost confidence."""
    est = estate()
    coverage = CoverageAnalyzer.summarize(
        est.identity("yusuf"), est.events, est, ANCHOR
    )
    assert coverage.capability_coverage == pytest.approx(0.25)
    assert confidence_from_coverage(coverage) < MIN_REPORTING_CONFIDENCE


def test_unknown_capability_findings_are_suppressed_not_reported():
    """Retained, but never reported as if understood."""
    results = {r.identity_id: r for r in RiskEngine().assess_estate(estate(), ANCHOR)}
    yusuf = results["yusuf"]
    assert yusuf.assessment.triggered_factors == ()
    assert yusuf.suppressed, "the grants must trip something, then be held back"


def test_capability_coverage_of_an_identity_with_no_grants_is_full():
    """
    Holding no access is the goal state, not a knowledge gap.

    Returning 0.0 here would punish an identity for having nothing to classify.
    """
    est = estate()
    coverage = CoverageAnalyzer.summarize(
        est.identity("alice"), est.events, est, ANCHOR
    )
    assert coverage.capability_coverage == 1.0


# --- The newly representable detection -------------------------------------


def test_standing_permission_management_fires():
    """viktor's finding was unrepresentable before the unification."""
    results = {r.identity_id: r for r in RiskEngine().assess_estate(estate(), ANCHOR)}
    factors = {
        f.factor_type.value for f in results["viktor"].assessment.triggered_factors
    }
    assert "EXCESSIVE_PRIVILEGE" in factors


def test_the_same_capability_held_jit_does_not_fire():
    """
    wendy holds exactly what viktor holds, on an equally critical resource.

    Only `GrantLifecycle` differs. If this fired, the engine would report no
    improvement after a successful remediation.
    """
    est = estate()
    viktor = est.identity("viktor").permissions[0]
    wendy = est.identity("wendy").permissions[0]
    assert viktor.action is wendy.action is Capability.MANAGE_PERMISSION
    assert est.resource(viktor.resource_id).sensitivity is est.resource(
        wendy.resource_id
    ).sensitivity

    results = {r.identity_id: r for r in RiskEngine().assess_estate(est, ANCHOR)}
    factors = {
        f.factor_type.value for f in results["wendy"].assessment.triggered_factors
    }
    assert "EXCESSIVE_PRIVILEGE" not in factors


# --- MANAGE_IDENTITY -------------------------------------------------------


def test_standing_identity_management_fires():
    """
    The quieter sibling of MANAGE_PERMISSION, and arguably the worse one.

    Rather than granting itself rights under its own name, this identity can
    create a principal, entitle it, and act as somebody else -- so the audit
    trail points at a user who never touched a keyboard.
    """
    results = {r.identity_id: r for r in RiskEngine().assess_estate(estate(), ANCHOR)}
    factors = {
        f.factor_type.value
        for f in results["svc_helpdesk"].assessment.triggered_factors
    }
    assert "EXCESSIVE_PRIVILEGE" in factors


def test_time_boxed_identity_management_does_not_fire():
    """
    zainab holds exactly what svc_helpdesk holds, on an equally critical
    directory. Only the lifecycle differs.

    If this fired, "we time-boxed it" would be indistinguishable from "we left
    it standing", which removes any reason to do the former.
    """
    est = estate()
    helpdesk = next(
        p
        for p in est.identity("svc_helpdesk").permissions
        if p.action is Capability.MANAGE_IDENTITY
    )
    zainab = next(
        p
        for p in est.identity("zainab").permissions
        if p.action is Capability.MANAGE_IDENTITY
    )
    assert helpdesk.action is zainab.action
    assert est.resource(helpdesk.resource_id).sensitivity is est.resource(
        zainab.resource_id
    ).sensitivity
    assert helpdesk.is_standing and not zainab.is_standing
    assert zainab.confers_access_at(ANCHOR), "the control must still be live access"

    results = {r.identity_id: r for r in RiskEngine().assess_estate(est, ANCHOR)}
    factors = {
        f.factor_type.value for f in results["zainab"].assessment.triggered_factors
    }
    assert "EXCESSIVE_PRIVILEGE" not in factors


# --- MANAGE_SECURITY_CONTROL -----------------------------------------------


def test_security_control_rights_fire_even_when_actively_used():
    """
    The finding rests on what the grant confers, not on disuse.

    svc_observability touches the audit pipeline every few days, so no
    staleness rule fires. An engine that only reported unused grants would
    never surface the most dangerous permission in the estate as long as
    somebody kept using it.
    """
    results = {r.identity_id: r for r in RiskEngine().assess_estate(estate(), ANCHOR)}
    result = results["svc_observability"]
    factors = {f.factor_type.value for f in result.assessment.triggered_factors}
    assert "EXCESSIVE_PRIVILEGE" in factors
    assert "STALE_ACCESS" not in factors


def test_reading_a_security_control_is_not_tampering_with_it():
    """
    tomas holds READ on a CRITICAL SIEM and reads it constantly.

    Keying on the resource being a security control, rather than on the
    capability held over it, would page about every SRE on the roster.
    """
    est = estate()
    tomas = est.identity("tomas").permissions[0]
    assert tomas.action is Capability.READ
    assert est.resource(tomas.resource_id).sensitivity is Sensitivity.CRITICAL

    results = {r.identity_id: r for r in RiskEngine().assess_estate(est, ANCHOR)}
    assert results["tomas"].assessment.triggered_factors == ()


def test_every_privileged_capability_is_measured():
    """
    Vocabulary that no scenario exercises is breadth recall cannot see.

    Every privileged capability must appear on at least one labelled subject's
    grants, so adding an enum member without scenarios fails here rather than
    quietly inflating the taxonomy.
    """
    est = estate()
    labelled = {
        f.subject_id for f in SyntheticConnector(anchor_time=ANCHOR).expected_findings()
    }
    held = {
        p.action
        for identity in est.identities
        if identity.id in labelled
        for p in identity.permissions
    }
    unmeasured = PRIVILEGED_CAPABILITIES - held
    assert unmeasured == set(), f"privileged capabilities with no scenario: {unmeasured}"
