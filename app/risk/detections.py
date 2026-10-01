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

from collections import Counter
from datetime import datetime, timedelta
from statistics import median
from typing import Callable, Optional

from app.models.event import Event, EventAction
from app.models.capability import (
    PERMISSION_ALTERING_CAPABILITIES,
    PRIVILEGED_CAPABILITIES,
    Capability,
)
from app.models.permission import GrantLifecycle
from app.models.identity import Identity
from app.models.resource import Resource, ResourceType, Sensitivity
from app.evidence.models import RecordKind
from app.graph.effective import EffectiveReach, ReachTier, TieredReach, grant_tier
from app.graph.semantics import effective_capabilities
from app.graph.graph import Edge, EdgeKind
from app.risk import scoring
from app.risk.blast_radius import STANDING as STANDING_CUT, blast_radius
from app.risk.models import RiskFactorType, RiskSubject, RiskSubjectType
from app.risk.rules import RuleContext, RuleOutcome
from app.risk.scoring import confidence_from_coverage

# --- Thresholds ------------------------------------------------------------

# A grant younger than this is not yet evidence of anything. Separates alice
# (420 days unused) from grace (2 days unused), which are otherwise identical.
MIN_GRANT_AGE_DAYS = 30.0

# Total silence beyond this, while holding standing access, reads as departure.
# The *floor* of the dormancy threshold, not the whole of it: an identity with
# an established rhythm of its own is judged against that rhythm instead (see
# CADENCE_TOLERANCE). Still set above the 85-day cadence of
# `seasonal_quarterly_batch`, so identities with too little history to have a
# rhythm are treated exactly as before.
DORMANT_IDENTITY_DAYS = 90.0

# Per-identity cadence. An identity whose activity days are typically N days
# apart is dormant only after CADENCE_TOLERANCE x N days of silence, and only
# when at least MIN_CADENCE_GAPS gaps establish that N -- three runs of a job
# are an anecdote, four are a rhythm. The baseline can only *raise* the
# threshold above the floor, never lower it: a busy daily identity going quiet
# for three weeks is a different finding, not dormancy.
#
# Calibrated 2026-09-29 on TRAIN only (the first honest cycle). Criterion
# declared before sweeping: the midpoint of the widest all-correct range. The
# range is (120/182, 160/91) = (0.66, 1.76), bounded by svc_semiannual_audit
# below and svc_quarterly_recon above; 1.5 sat 0.26 from the upper edge, 1.25
# is 0.59 from both. FRESH was read once, after this value was fixed.
CADENCE_TOLERANCE = 1.25
# Calibration cycle 2 (TRAIN only): exactly one value gets every TRAIN label
# right. 1 lets two data points 280 days apart pass as a "rhythm" (marta); 3
# calls a half-yearly job with three runs on record dormant (svc_key_rotation).
MIN_CADENCE_GAPS = 2

# The sensitivity line for standing privilege. HIGH was added on 2026-09-29 as
# a labelling decision, not a tuning one: standing admin is the thing to
# convert to JIT whether the resource is CRITICAL or HIGH. MEDIUM stays out --
# `admin_on_medium_internal_tool` is the trap that says so.
PRIVILEGED_SENSITIVITIES = frozenset({Sensitivity.HIGH, Sensitivity.CRITICAL})

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

# Blast radius: resources in standing reach (weighted, so UNKNOWN-only and
# never-observed ones do not count), at least one of them CRITICAL. Breadth
# gated on depth, as v1 -- but counted on reach, not grants.
BLAST_RADIUS_MIN_RESOURCES = 4
REAWAKENING_GAP_DAYS = 60.0
REAWAKENING_MIN_RECENT = 10
INTERACTIVE_LOGIN_THRESHOLD = 3

# Privilege creep: standing grants accumulated over time rather than issued
# together, mostly unexercised, reaching something valuable. The date spread
# is what separates creep from an onboarding batch with the same shape
# (`agent_scope_accretion` vs `onboarding_batch_grants`).
CREEP_MIN_GRANTS = 4
CREEP_MIN_GRANT_DATES = 3
CREEP_MIN_SPAN_DAYS = 60.0
CREEP_MIN_UNUSED_SHARE = 0.5

# Peer outlier: among the *other* holders of a HIGH+ resource, the share that
# sit in your department. Needs enough other holders for "nobody like you has
# this" to mean something.
PEER_MIN_OTHER_HOLDERS = 4
# Calibration cycle 2 (TRAIN only): all-correct for [0, 0.2) -- oscar is 0/4,
# the on-call SREs are 1/5 = 0.2 and must not fire. 0.25 sat outside that
# range; 0.1 is its midpoint. In words: "almost nobody in your department".
PEER_MAX_SAME_DEPT_SHARE = 0.1

# Bulk read: reads of HIGH+ data in any one hour of the last week, against the
# identity's own busiest hour before that week. Volume alone flags every ETL
# job; volume against the identity's own history flags the change.
BULK_READ_WINDOW = timedelta(hours=1)
BULK_READ_RECENT = timedelta(days=7)
BULK_READ_MIN = 50
BULK_READ_BASELINE_MULTIPLIER = 3.0

# How far the engine walks the graph for each identity (a hop is one grant or
# governs edge; stepping into a role is free), and the longest route the
# attack-path rule considers. **Compute bounds, not detection thresholds**
# (decided 2026-10-01): a long chain to a crown jewel is still a path, so it
# is reported with lower likelihood (`scoring.ATTACK_PATH_HOP_DECAY`) rather
# than declared harmless at some length nobody could defend. They need only a
# lower edge -- gustav and petra are two hops out, vesna six -- and are set
# well above it so no plausible chain is cut off.
REACH_MAX_HOPS = 8
ATTACK_PATH_MAX_HOPS = 8

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


def _peak_window(events: list[Event], window: timedelta) -> list[Event]:
    """The events inside the busiest window -- what a burst finding should cite."""
    if not events:
        return []
    ordered = sorted(events, key=lambda e: e.timestamp)
    best = (0, 1)
    start = 0
    for end in range(len(ordered)):
        while ordered[end].timestamp - ordered[start].timestamp > window:
            start += 1
        if end - start + 1 > best[1] - best[0]:
            best = (start, end + 1)
    return ordered[best[0] : best[1]]


def _exercised(ctx: RuleContext) -> set[tuple[str, EventAction]]:
    """(resource, action) pairs this identity has successfully performed."""
    return {(e.resource_id, e.action) for e in ctx.past_events() if e.success}


def _is_exercised(perm, exercised: set[tuple[str, EventAction]]) -> bool:
    permitted = GRANT_EXERCISED_BY.get(perm.action, set())
    return any((perm.resource_id, act) in exercised for act in permitted)


def _median_activity_gap_days(ctx: RuleContext) -> tuple[Optional[float], int]:
    """
    The identity's own rhythm: median gap between distinct activity days.

    Days, not events: a nightly job emitting a hundred events a night has a
    rhythm of one day, not of forty seconds. Returns (median, number of gaps).
    """
    days = sorted({e.timestamp.date() for e in ctx.past_events()})
    gaps = [(b - a).days for a, b in zip(days, days[1:])]
    if not gaps:
        return None, 0
    return float(median(gaps)), len(gaps)


def _grant_age_days(ctx: RuleContext, perm) -> Optional[float]:
    if perm.granted_at is None:
        return None
    return (ctx.evaluation_time - perm.granted_at).total_seconds() / 86400.0


def _cite_grants(ctx: RuleContext, grant_ids: list[str]) -> tuple[str, ...]:
    out: list[str] = []
    for gid in grant_ids:
        out.extend(ctx.cite(RecordKind.PERMISSION_GRANT, gid))
    return tuple(dict.fromkeys(out))


def _cite_path(ctx: RuleContext, path: tuple[Edge, ...]) -> tuple[str, ...]:
    """
    Every record a path rests on: each grant, and the resource record that
    declared each becomes/governs link. A multi-hop finding that cited only
    the first grant would explain none of the hops after it.
    """
    out: list[str] = []
    for edge in path:
        if edge.kind is EdgeKind.GRANT:
            out.extend(ctx.cite(RecordKind.PERMISSION_GRANT, edge.permission.id))
        else:
            out.extend(ctx.cite(RecordKind.RESOURCE, edge.source.id))
    return tuple(dict.fromkeys(out))


def _describe_path(origin: str, path: tuple[Edge, ...]) -> str:
    """A path as a reader follows it: who, which grant, which step, where."""
    out = [origin]
    for edge in path:
        if edge.kind is EdgeKind.GRANT:
            out.append(f"-{edge.permission.action.value}-> {edge.target.id}")
        elif edge.kind is EdgeKind.BECOMES:
            out.append(f"=becomes=> {edge.target.id}")
        else:
            out.append(f"~governs~> {edge.target.id}")
    return " ".join(out)


def _last_grant(path: tuple[Edge, ...]) -> Optional[Edge]:
    """The grant that confers the capability at the end of a path."""
    return next((e for e in reversed(path) if e.kind is EdgeKind.GRANT), None)


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
        if ctx.identity.is_break_glass:
            return RuleOutcome.no_finding()  # unused is its designed state
        exercised = _exercised(ctx)
        stale = []
        for perm in ctx.identity.permissions:
            if perm.lifecycle is not GrantLifecycle.STANDING:
                continue
            age = _grant_age_days(ctx, perm)
            if age is not None and age < MIN_GRANT_AGE_DAYS:
                continue
            if _is_exercised(perm, exercised):
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

    The offboarding-failure shape, judged against the identity's own rhythm.

    v1 used one global threshold, which is wrong in both directions for a
    scheduled job: a half-yearly audit export is "dormant" four months into
    every cycle, and nothing distinguishes a quarterly job that ran on time
    from one that silently stopped two quarters ago. v2 takes the larger of
    the global floor and CADENCE_TOLERANCE x the identity's median gap
    between activity days, once enough history exists to call it a rhythm.
    `semiannual_job_on_cadence` and `quarterly_job_missed_runs` are the pair.
    """

    rule_id = "dormant_identity.v2"
    factor_type = RiskFactorType.STALE_ACCESS

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        standing = [p for p in ctx.identity.permissions if p.is_standing]
        if not standing or ctx.identity.is_break_glass:
            return RuleOutcome.no_finding()

        threshold = DORMANT_IDENTITY_DAYS
        cadence, gaps = _median_activity_gap_days(ctx)
        if cadence is not None and gaps >= MIN_CADENCE_GAPS:
            threshold = max(threshold, CADENCE_TOLERANCE * cadence)

        last = ctx.features.last_event_timestamp
        if last is None:
            idle_days = None
        else:
            idle_days = (ctx.evaluation_time - last).total_seconds() / 86400.0
        if idle_days is not None and idle_days < threshold:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=7.0,
            likelihood=8.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"No activity for {idle_days:.0f} days (dormancy threshold for "
                f"this identity: {threshold:.0f}) while holding "
                f"{len(standing)} standing grant(s)."
                if idle_days is not None
                else f"No activity ever recorded, holding {len(standing)} standing grant(s)."
            ),
            recommendation="Confirm the identity is still in use; revoke all access if not.",
            evidence_ids=_cite_grants(ctx, [p.id for p in standing]),
        )


# --- EXCESSIVE_PRIVILEGE ---------------------------------------------------


class StandingPrivilegeOnHighValue:
    """
    Standing privileged capability over a HIGH or CRITICAL resource.

    Keyed on the action *joined to* what it is over. `admin_on_low_sensitivity_sandbox`
    and `admin_on_medium_internal_tool` are the controls: firing on the action
    alone flags every developer with a sandbox and teaches operators to ignore
    the finding everywhere.

    Supersedes `standing_privilege_on_critical.v1`, which drew the line at
    CRITICAL. A new id rather than a v2 because the name itself was the old
    line: an id that says "critical" while firing on HIGH would mislead
    everyone reading stored assessments.
    """

    rule_id = "standing_privilege_on_high_value.v1"
    factor_type = RiskFactorType.EXCESSIVE_PRIVILEGE

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        hits = []
        for perm in ctx.identity.permissions:
            if not perm.is_standing:
                continue
            if not perm.action.is_privileged:
                continue
            res = ctx.resource(perm.resource_id)
            if res is not None and res.sensitivity in PRIVILEGED_SENSITIVITIES:
                hits.append(perm)

        if not hits:
            return RuleOutcome.no_finding()

        critical = sum(
            1 for p in hits if ctx.resource(p.resource_id).sensitivity is Sensitivity.CRITICAL
        )
        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            # A crown jewel is worse than a merely valuable system; confidence
            # and likelihood do not change with the sensitivity, only impact.
            impact=9.0 if critical else 7.5,
            likelihood=8.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"Standing {', '.join(sorted({p.action.value for p in hits}))} on "
                f"{len(hits)} high-value resource(s), {critical} of them CRITICAL."
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

    Deliberately excludes plain ADMIN, which `StandingPrivilegeOnHighValue`
    already covers and which `admin_on_low_sensitivity_sandbox` proves must not
    fire on its own. Joined to sensitivity for the same reason: permission
    management over a scratch project is not the same finding.

    **v2 judges what the grant controls, not where it sits.** v1 read the
    sensitivity of the resource the grant is attached to, so permission
    management on a MEDIUM entitlements tool that governs a CRITICAL ledger
    (`governed_crown_jewel`) read clean. v2 walks the identity's standing
    effective reach and fires on any path whose *last grant* is explicit
    permission management and which ends on a HIGH+ resource: the direct case
    v1 caught, a `governs` hop, or a role stepped into on the way. "Last
    grant" is what keeps ADMIN out -- a manager's effective capabilities
    include manage_permission, but an admin path is the privilege rule's.
    Standing tier only: a JIT hop anywhere on the path is not standing power.
    Declines without a reach, like the peer rule without peers.
    """

    rule_id = "standing_permission_management.v2"
    factor_type = RiskFactorType.EXCESSIVE_PRIVILEGE

    EXPLICIT = PERMISSION_ALTERING_CAPABILITIES - {Capability.ADMIN}

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        if ctx.reach is None:
            return RuleOutcome.no_finding()

        hits = {}  # resource id -> (capability, path); first in sorted order wins
        for entry in ctx.reach.at_most(ReachTier.STANDING):
            if entry.capability not in self.EXPLICIT or entry.resource_id in hits:
                continue
            last = _last_grant(entry.path)
            if last is None or last.permission.action not in self.EXPLICIT:
                continue
            res = ctx.resource(entry.resource_id)
            if res is not None and res.sensitivity in PRIVILEGED_SENSITIVITIES:
                hits[entry.resource_id] = (last.permission.action, entry.path)

        if not hits:
            return RuleOutcome.no_finding()

        indirect = sorted(rid for rid, (_, path) in hits.items() if len(path) > 1)
        via = f", {len(indirect)} of them indirectly ({', '.join(indirect)})" if indirect else ""
        paths = [path for _, path in hits.values()]
        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=9.5,
            likelihood=8.5,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"Standing {', '.join(sorted({cap.value for cap, _ in hits.values()}))} over "
                f"{len(hits)} high-value resource(s){via}: this identity can grant "
                "itself any other permission."
            ),
            recommendation=(
                "Make permission management JIT-eligible with approval; standing "
                "rights here make every other control advisory."
            ),
            evidence_ids=tuple(
                dict.fromkeys(eid for path in paths for eid in _cite_path(ctx, path))
            ),
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


class StandingSecretAccess:
    """
    Standing access to a high-value secret store, whatever the capability.

    The action x resource join the capability taxonomy cannot express alone:
    READ on a wiki is ordinary, READ on a production vault is impersonation of
    every credential inside it. Treating secret reads as ordinary reads is how
    a "read-only" identity ends up holding the database password, the cloud
    root key and the signing key.

    Known limit: the engine sees the store, not the path. A service reading
    only its own secret and a human able to read every secret look identical
    here, which is why this rule is gated to HIGH+ stores rather than all.
    """

    rule_id = "standing_secret_access.v1"
    factor_type = RiskFactorType.EXCESSIVE_PRIVILEGE

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        hits = []
        for perm in ctx.identity.permissions:
            if not perm.is_standing or perm.action is Capability.AUTHENTICATE:
                continue
            res = ctx.resource(perm.resource_id)
            if (
                res is not None
                and res.resource_type is ResourceType.SECRET_STORE
                and res.sensitivity in PRIVILEGED_SENSITIVITIES
            ):
                hits.append(perm)

        if not hits:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=8.5,
            likelihood=8.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"Standing {', '.join(sorted({p.action.value for p in hits}))} on "
                f"{len(hits)} high-value secret store(s): reading a secret confers "
                "whatever that credential confers."
            ),
            recommendation=(
                "Issue secrets just-in-time or federate the workload; revoke "
                "standing reads on the store."
            ),
            evidence_ids=_cite_grants(ctx, [p.id for p in hits]),
        )


class PrivilegeCreep:
    """
    Standing grants that accumulated over months, mostly unused, reaching value.

    No single grant is excessive -- each was reasonable on the day it was
    issued. The finding is the process: access added on a cadence with nothing
    taking any away. The grant *dates* are the signal, which is why
    `onboarding_batch_grants` exists: the same five grants issued in one
    afternoon are a provisioning event, not creep.

    Requires most of the accumulated grants to be unexercised, because
    accumulation the identity demonstrably uses is a role that grew, not access
    that crept.
    """

    rule_id = "privilege_creep.v1"
    factor_type = RiskFactorType.EXCESSIVE_PRIVILEGE

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        standing = [
            p for p in ctx.identity.permissions if p.is_standing and p.granted_at is not None
        ]
        if len(standing) < CREEP_MIN_GRANTS:
            return RuleOutcome.no_finding()

        dates = sorted({p.granted_at.date() for p in standing})
        span = (dates[-1] - dates[0]).days
        if len(dates) < CREEP_MIN_GRANT_DATES or span < CREEP_MIN_SPAN_DAYS:
            return RuleOutcome.no_finding()

        if not any(
            (r := ctx.resource(p.resource_id)) is not None
            and r.sensitivity in PRIVILEGED_SENSITIVITIES
            for p in standing
        ):
            return RuleOutcome.no_finding()

        exercised = _exercised(ctx)
        unused = [p for p in standing if not _is_exercised(p, exercised)]
        if len(unused) / len(standing) < CREEP_MIN_UNUSED_SHARE:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=7.0,
            # Lower than the structural rules: an accumulation pattern is a
            # strong hint about process, a weaker claim about any one grant.
            likelihood=7.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"{len(standing)} standing grants added on {len(dates)} separate "
                f"dates over {span} days; {len(unused)} never exercised."
            ),
            recommendation=(
                "Review the whole set, not the newest grant; add an expiry or a "
                "periodic recertification so access stops accumulating."
            ),
            evidence_ids=_cite_grants(ctx, [p.id for p in standing]),
        )


# --- EXCESSIVE_BLAST_RADIUS ------------------------------------------------


class StandingBlastRadius:
    """
    Broad standing reach that includes at least one crown jewel.

    Breadth is gated on depth deliberately. `read_only_analyst_wide_access` has
    six standing grants and should never fire: counting grants unweighted flags
    the entire analytics organisation, which is the fastest way to make a
    blast-radius metric worthless.

    **v2 counts reach, not grants.** v1 counted standing grants, so it could
    not see a role the identity steps into or the ledger its console governs,
    and it counted four grants on *one* resource as breadth (yusuf). v2 reads
    the standing cut of the blast-radius score: at least
    `BLAST_RADIUS_MIN_RESOURCES` weighted resources, at least one CRITICAL.
    The gate is v1's shape on purpose -- the raw score mixes depth and breadth
    (one crown jewel alone is 30, above some genuine sprawl), and no TRAIN case
    yet bounds a score threshold on both sides. The score does two other jobs:
    it scales impact (`scoring.blast_impact`) and it explains the finding,
    heaviest resources first. Declines without a reach.

    Resources reached only through UNKNOWN capabilities count toward breadth
    and toward "reaches a CRITICAL" but add nothing to the score: an opaque
    grant is not privileged and not harmless. Coverage then decides whether
    the finding can be trusted (yusuf: it cannot, and it is suppressed).

    **v3 does not count stepping-stones** (`BlastRadius.stepping_stones`): a role
    resource is the door into a role whose reach is already counted through its
    grants. v2 counted the doors, so one long chain to one crown jewel read as
    breadth (vesna: six "resources", one of them a system). Decided on meaning
    by the user on 2026-10-01, when triaging FRESH v3's kai -- the same shape --
    exposed the contradiction with teodor/xenia. Built and checked on TRAIN.
    """

    rule_id = "standing_blast_radius.v3"
    factor_type = RiskFactorType.EXCESSIVE_BLAST_RADIUS

    SHOWN = 3

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        if ctx.reach is None:
            return RuleOutcome.no_finding()
        resources = {r.id: r for r in ctx.resources}
        radius = blast_radius(ctx.reach, resources, STANDING_CUT)
        unclassified = radius.unclassified_resources
        breadth = len(radius.contributions) + len(unclassified)
        if breadth < BLAST_RADIUS_MIN_RESOURCES:
            return RuleOutcome.no_finding()
        critical = radius.count_at(Sensitivity.CRITICAL) + sum(
            1 for rid in unclassified if resources[rid].sensitivity is Sensitivity.CRITICAL
        )
        if critical < 1:
            return RuleOutcome.no_finding()

        shown = ", ".join(
            f"{c.resource_id} {c.weight:.1f}" for c in radius.contributions[: self.SHOWN]
        )
        hidden = len(radius.contributions) - self.SHOWN
        more = f" and {hidden} more" if hidden > 0 else ""
        opaque = f", {len(unclassified)} unclassified" if unclassified else ""
        paths = [c.path for c in radius.contributions] + [
            e.path for e in ctx.reach.at_most(STANDING_CUT) if e.resource_id in unclassified
        ]
        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=scoring.blast_impact(radius.score),
            likelihood=8.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"{breadth} resources in standing reach{opaque}, {critical} "
                f"CRITICAL (blast radius {radius.score:.1f}): {shown}{more}."
            ),
            recommendation=(
                "Split into scoped roles; a single compromise currently reaches "
                "every one of these resources."
            ),
            evidence_ids=tuple(
                dict.fromkeys(eid for path in paths for eid in _cite_path(ctx, path))
            ),
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


class BulkReadBurst:
    """
    An hour of reading high-value data far beyond this identity's own history.

    The exfiltration shape, and the one where a global volume threshold fails
    hardest: a nightly ETL job reads more in an hour than most humans read in a
    year, every night, legitimately. So volume is measured against the
    identity's *own* busiest hour before the last week. `nightly_etl_on_schedule`
    is the control -- huge volume, but the same huge volume as always.

    An identity with no history before the window has a baseline of zero and
    fires on volume alone. Never understating access applies to reads too: a
    brand-new principal pulling fifty rows of customer data an hour is worth a
    look, not a free pass.
    """

    rule_id = "bulk_read_burst.v1"
    factor_type = RiskFactorType.ANOMALOUS_BEHAVIOR

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        reads = [
            e
            for e in ctx.past_events()
            if e.action is EventAction.READ
            and e.success
            and (r := ctx.resource(e.resource_id)) is not None
            and r.sensitivity in PRIVILEGED_SENSITIVITIES
        ]
        recent_start = ctx.evaluation_time - BULK_READ_RECENT
        recent = [e for e in reads if e.timestamp >= recent_start]
        burst = _peak_window(recent, BULK_READ_WINDOW)
        if len(burst) < BULK_READ_MIN:
            return RuleOutcome.no_finding()

        history = [e for e in reads if e.timestamp < recent_start]
        baseline = _max_in_window(history, BULK_READ_WINDOW)
        if baseline and len(burst) < BULK_READ_BASELINE_MULTIPLIER * baseline:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=8.5,
            likelihood=7.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"{len(burst)} reads of high-value data inside one hour; this "
                f"identity's busiest hour before this week was {baseline}."
            ),
            recommendation=(
                "Confirm the export was sanctioned; check where the data went and "
                "whether the identity's session was its own."
            ),
            evidence_ids=_cite_events(ctx, burst),
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


# The route search shared by the attack-path rule and choke-point analysis, so
# "what counts as a route to a crown jewel" is written once and cannot drift
# between the finding and the remediation advice.
LIVE_TIER = ReachTier.EXPIRED_ATTACHED


def controls(capability: Capability, resource: Resource) -> bool:
    """Control of a resource: a privileged capability, or reading a secret store."""
    if capability.is_privileged:
        return True
    return capability is Capability.READ and resource.resource_type is ResourceType.SECRET_STORE


def crown_jewel_routes(
    identity: Identity,
    reach: EffectiveReach,
    resource: Callable[[str], Optional[Resource]],
    at: datetime,
    *,
    skip: Callable[[TieredReach], bool] = lambda entry: False,
) -> dict[str, TieredReach]:
    """
    CRITICAL resources this identity controls only indirectly, with the route.

    Indirect: 2 to `ATTACK_PATH_MAX_HOPS` hops in the live cut, and no live
    direct grant on the target conferring control -- those belong to the
    privilege rules. One route per target: fewest hops, then easiest tier.
    """
    held_directly = set()
    for perm in identity.permissions:
        res = resource(perm.resource_id)
        if res is None or grant_tier(perm, at).rank > LIVE_TIER.rank:
            continue
        if any(controls(c, res) for c in effective_capabilities(perm.action)):
            held_directly.add(perm.resource_id)

    targets: dict[str, TieredReach] = {}
    for entry in reach.at_most(LIVE_TIER):
        if entry.resource_id in held_directly:
            continue
        if not 2 <= entry.hops <= ATTACK_PATH_MAX_HOPS:
            continue
        res = resource(entry.resource_id)
        if res is None or res.sensitivity is not Sensitivity.CRITICAL:
            continue
        if not controls(entry.capability, res) or skip(entry):
            continue
        current = targets.get(entry.resource_id)
        if current is None or (entry.hops, entry.tier.rank) < (current.hops, current.tier.rank):
            targets[entry.resource_id] = entry
    return targets


class AttackPathToCrownJewel:
    """
    Control of a crown jewel reachable only through someone or something else.

    The identity holds no grant on the CRITICAL resource that would show up in
    a permissions dump; it holds a grant on something *else* -- a role it can
    step into, a control plane that governs the target -- and the chain ends
    in control of the crown jewel. Every hop is individually authorised, which
    is why no per-grant rule sees it. `role_assumption_chain` watches such a
    chain being *walked* in events; this rule reports that it *exists*.

    Scope, as decided with the user (2026-09-30):

    * **Any indirect path** (2+ hops, up to `ATTACK_PATH_MAX_HOPS`) in the
      *live* cut: standing, temporary, or expired-but-attached. A JIT hop
      breaks it -- someone has to approve it.
    * **Minus what `standing_permission_management.v2` already reports**: a
      standing path whose last grant is explicit permission management. Same
      situation, one finding.
    * **Any origin, judged per target.** A target counts only if the identity
      has no *live direct* grant controlling it; the privilege rules own those.
      An admin who can also slip into a role controlling a different crown
      jewel is reported for that jewel.
    * **Control** means a privileged capability, or READ on a secret store.
    * An external origin raises likelihood: the path starts outside the trust
      boundary, and no resource-side check sees it.
    * Every hop past two lowers likelihood: each is another condition (MFA,
      session policy, source IP) this model does not evaluate, so a long chain
      is less certain to work end to end -- but it is still reported.

    One path per (resource, capability) is kept, so a target reachable both
    through a governs route perm-mgmt v2 reports and through an equally short
    role route may be reported only once, by v2. The finding exists either way.
    """

    rule_id = "attack_path_to_crown_jewel.v1"
    factor_type = RiskFactorType.PRIVILEGE_ESCALATION

    PERMISSION_MANAGEMENT = PERMISSION_ALTERING_CAPABILITIES - {Capability.ADMIN}

    @classmethod
    def reported_by_permission_management(cls, entry: TieredReach) -> bool:
        """A standing path ending in permission management: v2's finding, not ours."""
        last = _last_grant(entry.path)
        return (
            entry.tier is ReachTier.STANDING
            and last is not None
            and last.permission.action in cls.PERMISSION_MANAGEMENT
        )

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        if ctx.reach is None:
            return RuleOutcome.no_finding()
        targets = crown_jewel_routes(
            ctx.identity, ctx.reach, ctx.resource, ctx.evaluation_time,
            skip=self.reported_by_permission_management,
        )
        if not targets:
            return RuleOutcome.no_finding()

        ordered = sorted(targets.values(), key=lambda e: (e.hops, e.resource_id))
        first = ordered[0]
        others = f" (+{len(ordered) - 1} more)" if len(ordered) > 1 else ""
        origin = "External principal" if ctx.identity.is_external else "Identity"
        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=9.0,
            likelihood=scoring.attack_path_likelihood(first.hops, ctx.identity.is_external),
            confidence=confidence_from_coverage(ctx.coverage),
            description=(
                f"{origin} controls {len(ordered)} CRITICAL resource(s) it holds no grant "
                f"on, in {first.hops} hops ({first.tier.value}): "
                f"{_describe_path(ctx.identity.id, first.path)}{others}."
            ),
            recommendation=(
                "Break the chain at its cheapest link: make the first hop JIT-eligible, "
                "or remove the intermediate principal's standing grant."
            ),
            evidence_ids=tuple(
                dict.fromkeys(eid for e in ordered for eid in _cite_path(ctx, e.path))
            ),
        )


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


class PeerAccessOutlier:
    """
    Standing access to a high-value resource that nobody in your department holds.

    `department_context_mismatch` is the positive: four other people hold the
    payments ledger, all in Finance, and oscar is in Marketing. No fact about
    oscar alone is odd -- the grant is real and so is the department -- which
    is why this is the one rule that reads the cross-identity baseline.
    `finance_admin_on_finance_db` is the control: the same grant, held by
    someone whose department is exactly who holds it.

    Declines when there are too few other holders to form a peer group. A
    resource held by one other person says nothing about who it belongs to.
    """

    rule_id = "peer_access_outlier.v1"
    factor_type = RiskFactorType.CONTEXT_MISMATCH

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        if ctx.peers is None:
            return RuleOutcome.no_finding()

        hits = []
        detail = ""
        for perm in ctx.identity.permissions:
            if not perm.is_standing:
                continue
            res = ctx.resource(perm.resource_id)
            if res is None or res.sensitivity not in PRIVILEGED_SENSITIVITIES:
                continue
            others = ctx.peers.other_holders(perm.resource_id, ctx.identity.id)
            if len(others) < PEER_MIN_OTHER_HOLDERS:
                continue
            same = sum(1 for _, dept in others if dept == ctx.identity.department)
            if same / len(others) <= PEER_MAX_SAME_DEPT_SHARE:
                hits.append(perm)
                if not detail:
                    usual = Counter(dept for _, dept in others).most_common(1)[0][0]
                    detail = (
                        f"{len(others)} others hold {perm.resource_id}, {same} in "
                        f"{ctx.identity.department}; most are in {usual}."
                    )

        if not hits:
            return RuleOutcome.no_finding()

        return RuleOutcome(
            fired=True,
            subject=_identity_subject(ctx),
            impact=7.5,
            likelihood=7.0,
            confidence=confidence_from_coverage(ctx.coverage),
            description=detail,
            recommendation=(
                "Confirm the business reason with the resource owner; if there is "
                "none, revoke rather than convert to JIT."
            ),
            evidence_ids=_cite_grants(ctx, [p.id for p in hits]),
        )


# The registry the engine runs. Order is stable so assessments diff cleanly.
ALL_RULES: tuple = (
    UnusedStandingGrant(),
    ExpiredGrantStillAttached(),
    DormantIdentity(),
    StandingPrivilegeOnHighValue(),
    StandingPermissionManagement(),
    StandingSecurityControlAccess(),
    StandingSecretAccess(),
    PrivilegeCreep(),
    StandingBlastRadius(),
    FailedAuthBurst(),
    DestructiveBurst(),
    DormantThenActive(),
    BulkReadBurst(),
    EscalationAfterFailedAuth(),
    RevokeThenRegrant(),
    RoleAssumptionChain(),
    AttackPathToCrownJewel(),
    ExposedPrivilegedAccess(),
    ServiceAccountInteractiveLogin(),
    PeerAccessOutlier(),
)
