from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Sequence

from app.models.identity import Identity
from app.models.capability import PRIVILEGED_CAPABILITIES, Capability
from app.models.permission import GrantLifecycle, Permission
from app.models.resource import Exposure, Resource, Sensitivity
from app.models.event import Event, EventAction


@dataclass(frozen=True)
class IdentityFeatures:
    """
    An immutable data transfer object (DTO) representing the calculated features
    for a specific identity. It contains purely derived measurements/facts,
    strictly decoupled from any risk-scoring interpretations.
    """
    # --- Privilege features ---
    total_permission_count: int
    standing_permission_count: int
    temporary_permission_count: int
    jit_eligible_permission_count: int
    expired_permission_count: int
    privileged_permission_count: int
    critical_resource_permission_count: int
    standing_critical_permission_count: int

    # --- Exposure features ---
    # Counts only. Whether "standing admin on a public critical resource" is a
    # 9 or a 6 is a scoring judgement; these just say how many there are.
    exposed_resource_permission_count: int
    standing_exposed_permission_count: int
    privileged_exposed_permission_count: int
    exposed_critical_permission_count: int

    # --- Event features ---
    total_event_count: int
    failed_event_count: int
    failed_authentication_count: int
    recent_admin_action_count: int
    recent_event_count_24h: int
    recent_event_count_7d: int

    # --- Temporal features ---
    last_event_timestamp: Optional[datetime]
    last_privileged_event_timestamp: Optional[datetime]
    days_since_last_privileged_use: Optional[float]  # None if no previous privileged use exists

    # --- Resource features ---
    unique_resource_count_accessed: int
    critical_resource_count_accessed: int


# Classifications of Actions
#
# Both of these now derive from `PRIVILEGED_CAPABILITIES`, which is the whole
# point of the capability unification: there is one set, so a permission and an
# event can no longer disagree about what counts as privileged. The previous
# arrangement had two hand-maintained sets and they drifted twice.
#
# Kept as module names because they read well at the call sites and because
# `features.py` remains the documented place to look when asking what this
# engine treats as privileged.
PRIVILEGED_PERMISSION_ACTIONS = PRIVILEGED_CAPABILITIES

# Administrative *events* are the subset that changes who can do what, plus
# impersonation. Narrower than "privileged": a DELETE is privileged but is not
# an administrative action, and conflating them would make every bulk cleanup
# look like a permission change.
ADMIN_EVENT_ACTIONS = {
    action
    for action in EventAction
    if action.capability
    in {Capability.IMPERSONATE, Capability.MANAGE_PERMISSION, Capability.MANAGE_IDENTITY}
}


def _validate_tz_aware(dt: datetime, name: str) -> None:
    """Ensures that a datetime object is timezone-aware."""
    if not isinstance(dt, datetime):
        raise TypeError(f"{name} must be a datetime instance, got {type(dt).__name__}")
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"{name} must be timezone-aware")


class FeatureExtractor:
    """
    Computes stateless derived properties (features) from domain objects
    and telemetry events. Follows O(n) execution patterns using pre-computed lookups.
    """

    @staticmethod
    def extract_features(
        identity: Identity,
        resources: Sequence[Resource],
        events: Sequence[Event],
        evaluation_time: datetime,
    ) -> IdentityFeatures:
        """
        Extracts a cohesive, type-safe IdentityFeatures object for the given identity.

        All comparisons and filtering are relative to the provided evaluation_time.
        """
        _validate_tz_aware(evaluation_time, "evaluation_time")

        # 1. Create O(1) Resource lookup index once
        resource_map: dict[str, Resource] = {res.id: res for res in resources}

        # --- Privilege Calculations ---
        total_perms = len(identity.permissions)
        standing_perms = 0
        temp_perms = 0
        jit_eligible_perms = 0
        expired_perms = 0
        privileged_perms = 0
        critical_res_perms = 0
        standing_critical_perms = 0
        exposed_perms = 0
        standing_exposed_perms = 0
        privileged_exposed_perms = 0
        exposed_critical_perms = 0

        for perm in identity.permissions:
            if perm.is_standing:
                standing_perms += 1
            else:
                temp_perms += 1

            if perm.lifecycle is GrantLifecycle.JIT_ELIGIBLE:
                jit_eligible_perms += 1
            if perm.is_expired_at(evaluation_time):
                expired_perms += 1

            if perm.action in PRIVILEGED_PERMISSION_ACTIONS:
                privileged_perms += 1

            # Lookup resource safely. If resource is missing, we treat its sensitivity as unknown.
            res = resource_map.get(perm.resource_id)
            if res is not None and res.sensitivity == Sensitivity.CRITICAL:
                critical_res_perms += 1
                if perm.is_standing:
                    standing_critical_perms += 1

            # Exposure is a second axis, not a level of sensitivity: the two are
            # counted independently so scoring can weight their combination.
            # A missing resource is treated as unexposed for the same reason it
            # is treated as non-critical -- never raise, never speculate.
            if res is not None and res.exposure is Exposure.PUBLIC:
                exposed_perms += 1
                if perm.is_standing:
                    standing_exposed_perms += 1
                if perm.action in PRIVILEGED_PERMISSION_ACTIONS:
                    privileged_exposed_perms += 1
                if res.sensitivity == Sensitivity.CRITICAL:
                    exposed_critical_perms += 1

        # --- Event & Temporal Calculations ---
        # Filter events belonging to this identity and validate their timestamps are timezone-aware
        identity_events: list[Event] = []
        for ev in events:
            if ev.identity_id == identity.id:
                _validate_tz_aware(ev.timestamp, f"event {ev.id} timestamp")
                identity_events.append(ev)

        # Configurable boundaries: evaluation_time - window <= event.timestamp <= evaluation_time
        delta_24h = timedelta(hours=24)
        delta_7d = timedelta(days=7)

        total_evs = 0
        failed_evs = 0
        failed_auths = 0
        recent_admin_actions = 0
        evs_24h = 0
        evs_7d = 0

        last_ev_ts: Optional[datetime] = None
        last_priv_ev_ts: Optional[datetime] = None

        accessed_resources: set[str] = set()
        accessed_critical_resources: set[str] = set()

        for ev in identity_events:
            # We only evaluate events up to the evaluation_time. Events in the "future" are ignored.
            if ev.timestamp > evaluation_time:
                continue

            total_evs += 1

            # Event-specific aggregations
            if not ev.success:
                failed_evs += 1
                if ev.action == EventAction.LOGIN:
                    failed_auths += 1

            if ev.action in ADMIN_EVENT_ACTIONS:
                # We categorize actions like ASSUME_ROLE, GRANT_PERMISSION, REVOKE_PERMISSION as administrative behavior and apply a 24-hour time window
                if evaluation_time - delta_24h <= ev.timestamp <= evaluation_time:
                    recent_admin_actions += 1

            # Time window rolling aggregations
            if evaluation_time - delta_24h <= ev.timestamp <= evaluation_time:
                evs_24h += 1

            if evaluation_time - delta_7d <= ev.timestamp <= evaluation_time:
                evs_7d += 1

            # Tracking overall temporal high-water marks
            if last_ev_ts is None or ev.timestamp > last_ev_ts:
                last_ev_ts = ev.timestamp

            # Track privileged event execution. We map Perm Action to Event Action where applicable.
            # EventActions like login, admin actions (assume_role, grant/revoke) are considered privileged.
            # One assertion against one set. Previously this line hand-coded
            # `or ev.action == EventAction.DELETE` because the permission set
            # had forgotten destruction; now both sides read the same source.
            is_privileged_event = ev.action.is_privileged
            if is_privileged_event:
                if last_priv_ev_ts is None or ev.timestamp > last_priv_ev_ts:
                    last_priv_ev_ts = ev.timestamp

            # Resource interactions
            accessed_resources.add(ev.resource_id)
            res = resource_map.get(ev.resource_id)
            if res is not None and res.sensitivity == Sensitivity.CRITICAL:
                accessed_critical_resources.add(ev.resource_id)

        # Days since last privileged use calculation
        days_since_priv_use: Optional[float] = None
        if last_priv_ev_ts is not None:
            # Difference in fractional days
            delta = evaluation_time - last_priv_ev_ts
            days_since_priv_use = delta.total_seconds() / 86400.0

        return IdentityFeatures(
            total_permission_count=total_perms,
            standing_permission_count=standing_perms,
            temporary_permission_count=temp_perms,
            jit_eligible_permission_count=jit_eligible_perms,
            expired_permission_count=expired_perms,
            privileged_permission_count=privileged_perms,
            critical_resource_permission_count=critical_res_perms,
            standing_critical_permission_count=standing_critical_perms,
            exposed_resource_permission_count=exposed_perms,
            standing_exposed_permission_count=standing_exposed_perms,
            privileged_exposed_permission_count=privileged_exposed_perms,
            exposed_critical_permission_count=exposed_critical_perms,
            total_event_count=total_evs,
            failed_event_count=failed_evs,
            failed_authentication_count=failed_auths,
            recent_admin_action_count=recent_admin_actions,
            recent_event_count_24h=evs_24h,
            recent_event_count_7d=evs_7d,
            last_event_timestamp=last_ev_ts,
            last_privileged_event_timestamp=last_priv_ev_ts,
            days_since_last_privileged_use=days_since_priv_use,
            unique_resource_count_accessed=len(accessed_resources),
            critical_resource_count_accessed=len(accessed_critical_resources),
        )
