"""
The concrete rules.

Each is a small class satisfying `Rule` structurally, with an authored,
versioned `rule_id`. Thresholds live in module constants at the top so
calibration is a diff against one block rather than a hunt through bodies.

Every rule computes its own confidence from coverage. None of them special-case
a scenario: `stale_connector_blind_spot` and `incomplete_but_fresh_collection`
are handled entirely by the confidence floor in `scoring.py`, which is the
point of carrying confidence per finding rather than per report.
"""

from datetime import timedelta
from typing import Optional

from app.models.event import Event, EventAction
from app.models.capability import (
    PERMISSION_ALTERING_CAPABILITIES,
    PRIVILEGED_CAPABILITIES,
    Capability,
)
from app.models.permission import GrantLifecycle
from app.models.resource import Sensitivity
from app.evidence.models import RecordKind
from app.risk.models import RiskFactorType, RiskSubject, RiskSubjectType
from app.risk.rules import RuleContext, RuleOutcome
from app.risk.scoring import confidence_from_coverage

# --- Thresholds ------------------------------------------------------------

# A grant younger than this is not yet evidence of anything. Separates alice
# (420 days unused) from grace (2 days unused), which are otherwise identical.
MIN_GRANT_AGE_DAYS = 30.0

# Total silence beyond this, while holding standing access, reads as departure.
# Set above the 85-day cadence of `seasonal_quarterly_batch` on purpose: a
# global constant cannot model per-identity rhythm, so it is placed where it
# does least damage until a baseline layer exists.
DORMANT_IDENTITY_DAYS = 90.0

# Burst detection. Rate, never raw count -- `failed_logins_spread_thin` and
# `burst_then_escalation` both produce exactly 12 failed logins.
BURST_WINDOW = timedelta(hours=1)
FAILED_AUTH_BURST_THRESHOLD = 5
DESTRUCTIVE_BURST_WINDOW = timedelta(hours=24)
DESTRUCTIVE_BURST_THRESHOLD = 10

ESCALATION_WINDOW = timedelta(hours=24)
REGRANT_WINDOW = timedelta(hours=1)
ROLE_CHAIN_WINDOW = timedelta(hours=1)
ROLE_CHAIN_MIN_HOPS = 3

BLAST_RADIUS_MIN_GRANTS = 4
REAWAKENING_GAP_DAYS = 60.0
REAWAKENING_MIN_RECENT = 10
INTERACTIVE_LOGIN_THRESHOLD = 3

# Which event actions count as *exercising* a grant.
#
# Resource-level "was it touched?" is not good enough: julia holds standing
# DELETE on an archive and reads from it regularly, and treating that read as
# use of the delete grant hides the only dangerous thing she holds. A grant is
# exercised when an event occurs that the grant actually authorises.
#
# A successful LOGIN exercises every grant on that resource: you cannot
# authenticate to something you have no access to, so the access path is
# demonstrably live. Leaving it out produced two substantive false positives --
# marcus and svc_reporting both sign in to their resource constantly and were
# being reported as holding access they never use. Only *successful* events
# count, which is why svc_legacy_sync (a decade of failed logins and nothing
# else) still reads as stale.
_LOGIN = {EventAction.LOGIN}
GRANT_EXERCISED_BY: dict[Capability, set[EventAction]] = {
    Capability.READ: {EventAction.READ} | _LOGIN,
    Capability.WRITE: {EventAction.WRITE, EventAction.READ} | _LOGIN,
    Capability.DESTROY: {EventAction.DELETE} | _LOGIN,
    Capability.DEPLOY: {EventAction.WRITE, EventAction.ASSUME_ROLE} | _LOGIN,
    Capability.ADMIN: {
        EventAction.ASSUME_ROLE,
        EventAction.GRANT_PERMISSION,
        EventAction.REVOKE_PERMISSION,
        EventAction.DELETE,
        EventAction.WRITE,
    }
    | _LOGIN,
    Capability.IMPERSONATE: {EventAction.ASSUME_ROLE} | _LOGIN,
    Capability.MANAGE_PERMISSION: {
        EventAction.GRANT_PERMISSION,
        EventAction.REVOKE_PERMISSION,
    }
    | _LOGIN,
    Capability.MANAGE_IDENTITY: {
        EventAction.GRANT_PERMISSION,
        EventAction.REVOKE_PERMISSION,
    }
    | _LOGIN,
    Capability.MANAGE_SECURITY_CONTROL: {EventAction.WRITE, EventAction.DELETE} | _LOGIN,
    Capability.AUTHENTICATE: _LOGIN,
    # An UNKNOWN capability is exercised by *any* successful event on the
    # resource. We do not know what the grant authorises, so we cannot know
    # that it went unused -- and reporting "never exercised" on a grant we
    # failed to classify would manufacture a finding out of our own ignorance.
    # Under-reporting here is correct: the ignorance itself surfaces as
    # suppressed confidence, which is the honest channel for it.
    Capability.UNKNOWN: set(EventAction),
}


# --- Helpers ---------------------------------------------------------------


def _identity_subject(ctx: RuleContext) -> RiskSubject:
    return RiskSubject(subject_type=RiskSubjectType.IDENTITY, subject_id=ctx.identity.id)


def _max_in_window(events: list[Event], window: timedelta) -> int:
    """
    Largest number of the given events falling inside any sliding window.

    A two-pointer sweep over a sorted list, O(n). This is the function that
    separates a credential attack from a forgetful salesperson, and no scalar
    feature can stand in for it.
    """
    if not events:
        return 0
    stamps = sorted(e.timestamp for e in events)
    best = 1
    start = 0
    for end in range(len(stamps)):
        while stamps[end] - stamps[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def _grant_age_days(ctx: RuleContext, perm) -> Optional[float]:
    if perm.granted_at is None:
        return None
    return (ctx.evaluation_time - perm.granted_at).total_seconds() / 86400.0


def _cite_grants(ctx: RuleContext, grant_ids: list[str]) -> tuple[str, ...]:
    out: list[str] = []
    for gid in grant_ids:
        out.extend(ctx.cite(RecordKind.PERMISSION_GRANT, gid))
    return tuple(dict.fromkeys(out))


def _cite_events(ctx: RuleContext, events: list[Event]) -> tuple[str, ...]:
    out: list[str] = []
    for ev in events:
        out.extend(ctx.cite(RecordKind.ACTIVITY_EVENT, ev.id))
    return tuple(dict.fromkeys(out))


# --- STALE_ACCESS ----------------------------------------------------------


class UnusedStandingGrant:
    """
    A standing grant on a resource this identity has never touched.

    Per-grant, not per-identity. `dormant_standing_admin` exists precisely
    because alice is busy -- an identity-level "last activity" timestamp calls
    her healthy while the grant she holds admin over sits untouched for over a
    year.

    JIT-eligible grants are skipped: an unexercised JIT grant is the remediated
    end state this engine exists to produce, and firing on it would penalise
    every successful remediation.
    """

    rule_id = "unused_standing_grant.v1"
    factor_type = RiskFactorType.STALE_ACCESS

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        exercised: set[tuple[str, EventAction]] = {
            (e.resource_id, e.action) for e in ctx.past_events() if e.success
        }
        stale = []
        for perm in ctx.identity.permissions:
            if perm.lifecycle is not GrantLifecycle.STANDING:
                continue
            age = _grant_age_days(ctx, perm)
            if age is not None and age < MIN_GRANT_AGE_DAYS:
                continue
            permitted = GRANT_EXERCISED_BY.get(perm.action, set())
            if any((perm.resource_id, act) in exercised for act in permitted):
                continue
            stale.append(perm)

        if not stale:
            return RuleOutcome.no_finding()

        worst = max(
            stale,
            key=lambda p: (
                getattr(ctx.resource(p.resource_id), "sensitivity", Sensitivity.LOW)
                is Sensitivity.CRITICAL,
                p.action.is_privileged,
            ),
        )
        res = ctx.resource(worst.resource_id)
        critical = res is not None and res.sensitivity is Sensitivity.CRITICAL
        privileged = worst.action.is_privileged

        impact = 8.0 if (critical and privileged) else 6.0 if critical or privileged else 3.5
        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=impact,
            likelihood=9.0,  # the grant either was exercised or it was not
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"{len(stale)} standing grant(s) have never been exercised, including "
                f"{worst.action.value} on {worst.resource_id}."
            ),
            recommendation=(
                "Convert to JIT-eligible with an approval step and a short TTL, "
                "or revoke if no longer needed."
            ),
            evidence_ids=_cite_grants(ctx, [p.id for p in stale]),
        )


class ExpiredGrantStillAttached:
    """
    A time-bound grant whose expiry has passed and which is still present.

    Almost always a failed revocation rather than a policy choice, which is why
    likelihood is near-maximal: there is no ambiguity about whether the date
    has passed.
    """

    rule_id = "expired_grant_still_attached.v1"
    factor_type = RiskFactorType.STALE_ACCESS

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        expired = [p for p in ctx.identity.permissions if p.is_expired_at(ctx.evaluation_time)]
        if not expired:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=6.5,
            likelihood=9.5,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"{len(expired)} grant(s) are past their expiry but still attached "
                f"(earliest: {min(p.expires_at for p in expired).date()})."
            ),
            recommendation="Investigate why revocation did not run, then remove the grant.",
            evidence_ids=_cite_grants(ctx, [p.id for p in expired]),
        )


class DormantIdentity:
    """
    No activity of any kind for months, with standing access fully intact.

    The offboarding-failure shape. Known limitation: this uses a fixed global
    threshold, and `seasonal_quarterly_batch` is the scenario that shows why
    that is wrong -- an identity whose legitimate cadence is quarterly needs a
    per-identity baseline, which is a layer this engine does not yet have.
    """

    rule_id = "dormant_identity.v1"
    factor_type = RiskFactorType.STALE_ACCESS

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        standing = [p for p in ctx.identity.permissions if p.is_standing]
        if not standing:
            return RuleOutcome.no_finding()

        last = ctx.features.last_event_timestamp
        if last is None:
            idle_days = None
        else:
            idle_days = (ctx.evaluation_time - last).total_seconds() / 86400.0
        if idle_days is not None and idle_days < DORMANT_IDENTITY_DAYS:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=7.0,
            likelihood=8.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"No activity for {idle_days:.0f} days while holding "
                f"{len(standing)} standing grant(s)."
                if idle_days is not None
                else f"No activity ever recorded, holding {len(standing)} standing grant(s)."
            ),
            recommendation="Confirm the identity is still in use; revoke all access if not.",
            evidence_ids=_cite_grants(ctx, [p.id for p in standing]),
        )


# --- EXCESSIVE_PRIVILEGE ---------------------------------------------------


class StandingPrivilegeOnCritical:
    """
    Standing admin/deploy/delete over a CRITICAL resource.

    Keyed on the action *joined to* what it is over. `admin_on_low_sensitivity_sandbox`
    is the control: firing on the action alone flags every developer with a
    sandbox and teaches operators to ignore the finding everywhere.
    """

    rule_id = "standing_privilege_on_critical.v1"
    factor_type = RiskFactorType.EXCESSIVE_PRIVILEGE

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        hits = []
        for perm in ctx.identity.permissions:
            if not perm.is_standing:
                continue
            if not perm.action.is_privileged:
                continue
            res = ctx.resource(perm.resource_id)
            if res is not None and res.sensitivity is Sensitivity.CRITICAL:
                hits.append(perm)

        if not hits:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=9.0,
            likelihood=8.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"Standing {', '.join(sorted({p.action.value for p in hits}))} on "
                f"{len(hits)} CRITICAL resource(s)."
            ),
            recommendation="Replace standing access with JIT elevation and an approval gate.",
            evidence_ids=_cite_grants(ctx, [p.id for p in hits]),
        )


class StandingPermissionManagement:
    """
    Standing power to change who can do what, over a high-value control plane.

    This detection was **unrepresentable before the capability unification**.
    `PermissionAction` had no member for it, so an identity holding the right
    to attach policies or mint credentials looked identical to one holding
    ordinary write, and the only way to notice was to watch it grant something
    -- after the fact. Holding the keys is the finding; using them is an event.

    It is the sharpest capability in any IAM system: whoever holds it can grant
    themselves every other capability, which makes every other control
    advisory.

    Deliberately excludes plain ADMIN, which `StandingPrivilegeOnCritical`
    already covers and which `admin_on_low_sensitivity_sandbox` proves must not
    fire on its own. Joined to sensitivity for the same reason: permission
    management over a scratch project is not the same finding.
    """

    rule_id = "standing_permission_management.v1"
    factor_type = RiskFactorType.EXCESSIVE_PRIVILEGE

    EXPLICIT = PERMISSION_ALTERING_CAPABILITIES - {Capability.ADMIN}

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        hits = []
        for perm in ctx.identity.permissions:
            if not perm.is_standing or perm.action not in self.EXPLICIT:
                continue
            res = ctx.resource(perm.resource_id)
            if res is not None and res.sensitivity in {
                Sensitivity.HIGH,
                Sensitivity.CRITICAL,
            }:
                hits.append(perm)

        if not hits:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=9.5,
            likelihood=8.5,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"Standing {', '.join(sorted({p.action.value for p in hits}))} on "
                f"{len(hits)} high-value resource(s): this identity can grant "
                "itself any other permission."
            ),
            recommendation=(
                "Make permission management JIT-eligible with approval; standing "
                "rights here make every other control advisory."
            ),
            evidence_ids=_cite_grants(ctx, [p.id for p in hits]),
        )


class StandingSecurityControlAccess:
    """
    Standing power to switch off the controls that would notice an incident.

    Distinct from ordinary privilege because of *who it blinds*. Deleting a
    database destroys data and leaves a trail; stopping CloudTrail or disabling
    backups destroys the trail itself, so every other detection in this engine
    -- including the ones watching this identity -- silently stops working.
    That is why likelihood is high and impact is near the ceiling even though
    no data is touched.

    It is also the capability with the worst detectability profile: tampering
    is usually visible only in the logs the tampering removes, so the holding
    is far more reliably observable than the act. Reporting the grant is the
    only dependable option.

    Sensitivity-gated like the other privilege rules, so a developer who can
    silence alerting on a scratch environment does not read the same as one who
    can stop the audit pipeline.
    """

    rule_id = "standing_security_control_access.v1"
    factor_type = RiskFactorType.EXCESSIVE_PRIVILEGE

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        hits = []
        for perm in ctx.identity.permissions:
            if not perm.is_standing:
                continue
            if perm.action is not Capability.MANAGE_SECURITY_CONTROL:
                continue
            res = ctx.resource(perm.resource_id)
            if res is not None and res.sensitivity in {
                Sensitivity.HIGH,
                Sensitivity.CRITICAL,
            }:
                hits.append(perm)

        if not hits:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=9.0,
            likelihood=8.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"Standing rights to disable security controls on {len(hits)} "
                "high-value resource(s): this identity can turn off the "
                "monitoring that would report its own actions."
            ),
            recommendation=(
                "Require approval and a second pair of eyes for control changes; "
                "ship audit logs somewhere this identity cannot reach."
            ),
            evidence_ids=_cite_grants(ctx, [p.id for p in hits]),
        )


# --- EXCESSIVE_BLAST_RADIUS ------------------------------------------------


class StandingBlastRadius:
    """
    Broad standing access that reaches at least one crown jewel.

    Breadth is gated on depth deliberately. `read_only_analyst_wide_access` has
    six standing grants and should never fire: counting grants unweighted flags
    the entire analytics organisation, which is the fastest way to make a
    blast-radius metric worthless.
    """

    rule_id = "standing_blast_radius.v1"
    factor_type = RiskFactorType.EXCESSIVE_BLAST_RADIUS

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        f = ctx.features
        if f.standing_permission_count < BLAST_RADIUS_MIN_GRANTS:
            return RuleOutcome.no_finding()
        if f.standing_critical_permission_count < 1:
            return RuleOutcome.no_finding()

        standing = [p for p in ctx.identity.permissions if p.is_standing]
        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=8.5,
            likelihood=8.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"{f.standing_permission_count} standing grants spanning "
                f"{f.standing_critical_permission_count} CRITICAL resource(s)."
            ),
            recommendation=(
                "Split into scoped roles; a single compromise currently reaches "
                "every one of these resources."
            ),
            evidence_ids=_cite_grants(ctx, [p.id for p in standing]),
        )


# --- ANOMALOUS_BEHAVIOR ----------------------------------------------------


class FailedAuthBurst:
    """
    Many failed logins compressed into a short window.

    Rate, not count. `burst_then_escalation` and `failed_logins_spread_thin`
    both produce exactly twelve failed logins; one is eighteen per hour and the
    other is two per week. Any rule reading `failed_authentication_count` is
    wrong on one of them no matter where the threshold sits.
    """

    rule_id = "failed_auth_burst.v1"
    factor_type = RiskFactorType.ANOMALOUS_BEHAVIOR

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        failures = [
            e
            for e in ctx.past_events()
            if e.action is EventAction.LOGIN and not e.success
        ]
        peak = _max_in_window(failures, BURST_WINDOW)
        if peak < FAILED_AUTH_BURST_THRESHOLD:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=6.0,
            likelihood=8.5,
            confidence=confidence_from_coverage(ctx.coverage),
            description=f"{peak} failed logins inside a single hour.",
            recommendation="Lock the credential and check for a successful login after the burst.",
            evidence_ids=_cite_events(ctx, failures),
        )


class DestructiveBurst:
    """Many deletes in a short window against a high-value resource."""

    rule_id = "destructive_burst.v1"
    factor_type = RiskFactorType.ANOMALOUS_BEHAVIOR

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        deletes = [
            e
            for e in ctx.past_events()
            if e.action is EventAction.DELETE and e.success
        ]
        peak = _max_in_window(deletes, DESTRUCTIVE_BURST_WINDOW)
        if peak < DESTRUCTIVE_BURST_THRESHOLD:
            return RuleOutcome.no_finding()

        sensitive = any(
            (r := ctx.resource(e.resource_id)) is not None
            and r.sensitivity in {Sensitivity.HIGH, Sensitivity.CRITICAL}
            for e in deletes
        )
        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=9.0 if sensitive else 5.5,
            likelihood=8.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=f"{peak} destructive actions inside 24 hours.",
            recommendation="Verify this was an intended bulk operation; check backups and retention policy.",
            evidence_ids=_cite_events(ctx, deletes),
        )


class DormantThenActive:
    """
    A long silence ending in a burst of activity.

    Neither half is suspicious: dormancy is common and a busy afternoon is
    normal. The transition is the signal, which means the rule has to look at
    the shape of the timeline rather than any single window.
    """

    rule_id = "dormant_then_active.v1"
    factor_type = RiskFactorType.ANOMALOUS_BEHAVIOR

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        events = ctx.past_events()
        if ctx.features.recent_event_count_24h < REAWAKENING_MIN_RECENT:
            return RuleOutcome.no_finding()

        recent_start = ctx.evaluation_time - timedelta(hours=24)
        prior = [e for e in events if e.timestamp < recent_start]
        if not prior:
            return RuleOutcome.no_finding()

        gap_days = (recent_start - max(e.timestamp for e in prior)).total_seconds() / 86400.0
        if gap_days < REAWAKENING_GAP_DAYS:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=7.5,
            likelihood=7.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"Silent for {gap_days:.0f} days, then "
                f"{ctx.features.recent_event_count_24h} actions in 24 hours."
            ),
            recommendation="Confirm with the owner that this reactivation was expected.",
            evidence_ids=_cite_events(ctx, list(events)),
        )


# --- PRIVILEGE_ESCALATION --------------------------------------------------


class EscalationAfterFailedAuth:
    """
    A successful privilege change shortly after a failed-login burst.

    The pairing is the finding. `credential_stuffing_no_success` is the control:
    thirty failed logins with nothing succeeding is a *working* control, and
    reporting it as an escalation manufactures an incident out of a blocked
    attack.
    """

    rule_id = "escalation_after_failed_auth.v1"
    factor_type = RiskFactorType.PRIVILEGE_ESCALATION

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        events = ctx.past_events()
        failures = [e for e in events if e.action is EventAction.LOGIN and not e.success]
        if _max_in_window(failures, BURST_WINDOW) < FAILED_AUTH_BURST_THRESHOLD:
            return RuleOutcome.no_finding()

        last_failure = max(e.timestamp for e in failures)
        escalations = [
            e
            for e in events
            if e.success
            and e.action in {EventAction.GRANT_PERMISSION, EventAction.ASSUME_ROLE}
            and last_failure <= e.timestamp <= last_failure + ESCALATION_WINDOW
        ]
        if not escalations:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=9.5,
            likelihood=8.5,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"{len(escalations)} successful privilege change(s) within "
                f"{ESCALATION_WINDOW} of a failed-login burst."
            ),
            recommendation="Treat as a suspected takeover: revoke sessions and audit the new grants.",
            evidence_ids=_cite_events(ctx, failures + escalations),
        )


class RevokeThenRegrant:
    """A revoke closely followed by a re-grant: the shape of covering tracks."""

    rule_id = "revoke_then_regrant.v1"
    factor_type = RiskFactorType.PRIVILEGE_ESCALATION

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        events = ctx.past_events()
        revokes = [e for e in events if e.action is EventAction.REVOKE_PERMISSION and e.success]
        grants = [e for e in events if e.action is EventAction.GRANT_PERMISSION and e.success]

        for rev in revokes:
            for grant in grants:
                if rev.timestamp <= grant.timestamp <= rev.timestamp + REGRANT_WINDOW:
                    gap = (grant.timestamp - rev.timestamp).total_seconds() / 60.0
                    return RuleOutcome(
                        fired=True,
                        subject=_identity_subject(ctx),
                        impact=8.5,
                        likelihood=7.5,
                        confidence=confidence_from_coverage(ctx.coverage),
                        description=(
                            f"A permission was revoked and re-granted {gap:.0f} minutes later."
                        ),
                        recommendation="Review both changes and who authorised them.",
                        evidence_ids=_cite_events(ctx, [rev, grant]),
                    )
        return RuleOutcome.no_finding()


class RoleAssumptionChain:
    """
    Several role assumptions across distinct resources in one short window.

    Every hop is individually authorised, so no per-event check can see this.
    Distinct resources matter: repeatedly assuming the same role is routine
    work, which is what keeps `admin_on_low_sensitivity_sandbox` quiet here.
    """

    rule_id = "role_assumption_chain.v1"
    factor_type = RiskFactorType.PRIVILEGE_ESCALATION

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        hops = [
            e
            for e in ctx.past_events()
            if e.action is EventAction.ASSUME_ROLE and e.success
        ]
        if len(hops) < ROLE_CHAIN_MIN_HOPS:
            return RuleOutcome.no_finding()

        best_chain: list[Event] = []
        start = 0
        for end in range(len(hops)):
            while hops[end].timestamp - hops[start].timestamp > ROLE_CHAIN_WINDOW:
                start += 1
            window = hops[start : end + 1]
            if len({e.resource_id for e in window}) > len(
                {e.resource_id for e in best_chain}
            ):
                best_chain = window

        if len({e.resource_id for e in best_chain}) < ROLE_CHAIN_MIN_HOPS:
            return RuleOutcome.no_finding()

        terminal = best_chain[-1]
        res = ctx.resource(terminal.resource_id)
        critical = res is not None and res.sensitivity is Sensitivity.CRITICAL
        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=9.0 if critical else 6.5,
            likelihood=7.5,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"{len({e.resource_id for e in best_chain})} role assumptions across "
                f"distinct resources within an hour, ending at {terminal.resource_id}."
            ),
            recommendation="Review the trust relationships that made this chain traversable.",
            evidence_ids=_cite_events(ctx, best_chain),
        )


# --- EXTERNAL_EXPOSURE -----------------------------------------------------


class ExposedPrivilegedAccess:
    """
    Privileged access reachable from outside the trust boundary.

    Both sides of exposure. Resource-side is a public endpoint; identity-side is
    a principal outside our IdP holding access to something internal, which
    every resource-side check reads as clean.

    Exposure is joined to sensitivity, never used alone: `public_by_design_marketing_site`
    is PUBLIC on both resources and must stay silent, because a rule firing on
    reachability alone flags every status page in the estate.
    """

    rule_id = "exposed_privileged_access.v1"
    factor_type = RiskFactorType.EXTERNAL_EXPOSURE

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        f = ctx.features
        resource_side = f.exposed_critical_permission_count > 0
        identity_side = ctx.identity.is_external and f.standing_critical_permission_count > 0

        if not (resource_side or identity_side):
            return RuleOutcome.no_finding()

        if resource_side:
            detail = (
                f"{f.exposed_critical_permission_count} grant(s) on CRITICAL resources "
                "that are reachable from the public internet."
            )
        else:
            detail = (
                f"An external principal holds {f.standing_critical_permission_count} "
                "standing grant(s) on CRITICAL resources."
            )

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=9.5,
            likelihood=8.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=detail,
            recommendation=(
                "Remove public reachability or reduce the grant; external access to "
                "crown jewels should be brokered, not standing."
            ),
            evidence_ids=_cite_grants(
                ctx, [p.id for p in ctx.identity.permissions]
            ),
        )


# --- CONTEXT_MISMATCH ------------------------------------------------------


class ServiceAccountInteractiveLogin:
    """
    A service identity authenticating interactively.

    Service accounts use keys, not sessions. Repeated successful logins usually
    mean a human is wearing the credential, which destroys attribution for
    everything that principal subsequently does.
    """

    rule_id = "service_account_interactive_login.v1"
    factor_type = RiskFactorType.CONTEXT_MISMATCH

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        from app.models.identity import IdentityType

        if ctx.identity.identity_type is not IdentityType.SERVICE:
            return RuleOutcome.no_finding()

        logins = [
            e for e in ctx.past_events() if e.action is EventAction.LOGIN and e.success
        ]
        if len(logins) < INTERACTIVE_LOGIN_THRESHOLD:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=6.0,
            likelihood=7.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"{len(logins)} successful interactive logins by a service identity."
            ),
            recommendation="Move to key-based auth and find out who is using the credential.",
            evidence_ids=_cite_events(ctx, logins),
        )


# The registry the engine runs. Order is stable so assessments diff cleanly.
ALL_RULES: tuple = (
    UnusedStandingGrant(),
    ExpiredGrantStillAttached(),
    DormantIdentity(),
    StandingPrivilegeOnCritical(),
    StandingPermissionManagement(),
    StandingSecurityControlAccess(),
    StandingBlastRadius(),
    FailedAuthBurst(),
    DestructiveBurst(),
    DormantThenActive(),
    EscalationAfterFailedAuth(),
    RevokeThenRegrant(),
    RoleAssumptionChain(),
    ExposedPrivilegedAccess(),
    ServiceAccountInteractiveLogin(),
)
