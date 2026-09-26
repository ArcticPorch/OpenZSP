"""
The capability taxonomy: one vocabulary for what an identity can do.

This replaced a `PermissionAction` enum that had five members and did not line
up with `EventAction`, a mismatch that produced two bugs from one flaw:

  * `DELETE` was a privileged *event* but not a privileged *permission*, so an
    identity holding standing delete on a crown jewel scored
    `privileged_permission_count == 0` until it actually destroyed something.
  * `GRANT_PERMISSION` / `ASSUME_ROLE` / `REVOKE_PERMISSION` were observable as
    events but **unholdable as permissions**. You could watch an identity
    exercise permission-granting power; you could not model it holding that
    power. In real IAM that is the top of the hierarchy -- the capability that
    makes every other permission reachable -- and it was the one thing the
    permission model could not say.

With a single enum, "privileged" is asserted once, against capabilities, and
the two sets cannot disagree because there is only one set.

### Why this does not grow with the cloud

AWS alone has 10,000+ IAM actions across 400+ services and adds more weekly.
This enum does not track them and must never try: an enum of action strings
would break on every service release and would still be useless for Entra,
Okta, Snowflake or GitHub, leaving five incompatible vocabularies and no shared
rules.

Actions are enumerable in the thousands; *classes of harm* are not. There are
roughly a dozen, they are stable across providers, and they are what detection
rules actually reason about. So reality is normalized down to this taxonomy at
ingestion -- each connector owns its own mapping table -- and rules never see a
provider's vocabulary at all. Adding a third cloud is a connector plus a table,
with no rule changes.

### Why UNKNOWN exists and must never be defaulted away

An action this taxonomy does not recognise becomes `UNKNOWN` and the grant is
**retained**. Dropping it would understate access, which the normalizer already
identifies as the one direction a privilege engine must not err in. Mapping it
to `READ` instead would be worse: a silent, confident understatement.

`UNKNOWN` is deliberately not privileged and deliberately not harmless. It
flows into `CoverageSummary` and suppresses confidence, so "we do not
understand a third of this identity's permissions" surfaces as a low-confidence
finding rather than a clean report -- the same discipline the blind-spot
scenarios enforce for stale collection.
"""

from enum import Enum


class Capability(Enum):
    """What a grant confers, or what an event exercised."""

    # --- Ordinary access ---
    AUTHENTICATE = "authenticate"  # establish a session against a resource
    READ = "read"
    WRITE = "write"

    # --- Privileged ---
    DESTROY = "destroy"  # delete, terminate, purge
    DEPLOY = "deploy"  # ship code or infrastructure
    IMPERSONATE = "impersonate"  # assume a role, act-as another principal
    MANAGE_PERMISSION = "manage_permission"  # attach policy, grant, revoke
    MANAGE_IDENTITY = "manage_identity"  # create, disable, reset credentials
    MANAGE_SECURITY_CONTROL = "manage_security_control"  # disable logging, backups
    ADMIN = "admin"  # unrestricted; implies all of the above

    # --- The honest gap ---
    UNKNOWN = "unknown"

    @property
    def is_privileged(self) -> bool:
        return self in PRIVILEGED_CAPABILITIES

    @classmethod
    def from_token(cls, raw: object) -> "Capability":
        """
        Best-effort translation of a source's action string. Never raises.

        Returns `UNKNOWN` rather than failing, because a grant we cannot
        classify is still a grant, and losing it understates access.

        The heuristics here are the last resort, not the plan. A real connector
        should carry an explicit table -- AWS already publishes one, since the
        IAM Service Authorization Reference classifies every action by access
        level and its "Permissions management" category hands you
        MANAGE_PERMISSION for free. Verb matching covers the long tail after
        that table has taken the actions that matter.
        """
        if isinstance(raw, cls):
            return raw
        if not isinstance(raw, str):
            return cls.UNKNOWN

        token = raw.strip().lower()
        if not token:
            return cls.UNKNOWN

        try:
            return cls(token)
        except ValueError:
            pass

        if token in _ALIASES:
            return _ALIASES[token]

        # Provider-qualified forms such as "s3:DeleteObject" or
        # "okta.user.lifecycle.suspend": try the most specific segment first.
        for sep in (":", "."):
            if sep in token:
                tail = token.rsplit(sep, 1)[-1]
                if tail != token:
                    resolved = cls.from_token(tail)
                    if resolved is not cls.UNKNOWN:
                        return resolved

        for prefix, capability in _VERB_PREFIXES:
            if token.startswith(prefix):
                return capability

        return cls.UNKNOWN


# The single source of truth for "privileged". Both permissions and events
# assert against this, which is what makes it impossible for the two to drift.
#
# AUTHENTICATE is absent on purpose: being able to log in is the precondition
# for access, not an elevation of it, and treating it as privileged would mark
# essentially every identity in the estate.
#
# UNKNOWN is absent too. An unclassified capability is a coverage problem, and
# treating it as privileged would manufacture findings out of our own ignorance
# rather than suppressing confidence, which is what actually happens to it.
PRIVILEGED_CAPABILITIES: frozenset[Capability] = frozenset(
    {
        Capability.ADMIN,
        Capability.DEPLOY,
        Capability.DESTROY,
        Capability.IMPERSONATE,
        Capability.MANAGE_PERMISSION,
        Capability.MANAGE_IDENTITY,
        Capability.MANAGE_SECURITY_CONTROL,
    }
)

# Capabilities that change who can do what. The sharpest subset: holding these
# means being able to grant yourself everything else.
PERMISSION_ALTERING_CAPABILITIES: frozenset[Capability] = frozenset(
    {
        Capability.ADMIN,
        Capability.MANAGE_PERMISSION,
        Capability.MANAGE_IDENTITY,
    }
)

_ALIASES: dict[str, Capability] = {
    "delete": Capability.DESTROY,
    "terminate": Capability.DESTROY,
    "purge": Capability.DESTROY,
    "remove": Capability.DESTROY,
    "login": Capability.AUTHENTICATE,
    "signin": Capability.AUTHENTICATE,
    "assume_role": Capability.IMPERSONATE,
    "assumerole": Capability.IMPERSONATE,
    "passrole": Capability.IMPERSONATE,
    "act_as": Capability.IMPERSONATE,
    "grant_permission": Capability.MANAGE_PERMISSION,
    "revoke_permission": Capability.MANAGE_PERMISSION,
    "attachuserpolicy": Capability.MANAGE_PERMISSION,
    "attachrolepolicy": Capability.MANAGE_PERMISSION,
    "putuserpolicy": Capability.MANAGE_PERMISSION,
    "createaccesskey": Capability.MANAGE_IDENTITY,
    "createuser": Capability.MANAGE_IDENTITY,
    "resetpassword": Capability.MANAGE_IDENTITY,
    "stoplogging": Capability.MANAGE_SECURITY_CONTROL,
    "deletetrail": Capability.MANAGE_SECURITY_CONTROL,
    "disablebackup": Capability.MANAGE_SECURITY_CONTROL,
    "owner": Capability.ADMIN,
    "root": Capability.ADMIN,
    "release": Capability.DEPLOY,
    "publish": Capability.DEPLOY,
}

# Ordered: the first match wins, so more specific prefixes come first.
_VERB_PREFIXES: tuple[tuple[str, Capability], ...] = (
    ("deleteobject", Capability.DESTROY),
    ("delete", Capability.DESTROY),
    ("terminate", Capability.DESTROY),
    ("get", Capability.READ),
    ("list", Capability.READ),
    ("describe", Capability.READ),
    ("read", Capability.READ),
    ("batchget", Capability.READ),
    ("create", Capability.WRITE),
    ("put", Capability.WRITE),
    ("update", Capability.WRITE),
    ("modify", Capability.WRITE),
    ("write", Capability.WRITE),
    ("set", Capability.WRITE),
)
