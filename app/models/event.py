from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from app.common.validation import validate_non_empty_str, validate_tz_datetime
from app.models.capability import Capability


class EventAction(Enum):
    """
    What was observed happening. Finer-grained than `Capability` on purpose.

    Events keep their own vocabulary because *which* privileged thing happened
    matters to detection in a way it does not to entitlement: a revoke followed
    by a grant is the shape of covering tracks, and collapsing both into
    MANAGE_PERMISSION at ingestion would erase the sequence that makes it a
    finding. Permissions answer "what could they do", events answer "what did
    they do", and `capability` is the axis on which the two are compared.
    """

    LOGIN = "login"
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ASSUME_ROLE = "assume_role"
    GRANT_PERMISSION = "grant_permission"
    REVOKE_PERMISSION = "revoke_permission"

    @property
    def capability(self) -> Capability:
        """The capability this action exercises."""
        return _EVENT_CAPABILITIES[self]

    @property
    def is_privileged(self) -> bool:
        """
        Asserted against the same set permissions use.

        This is the property that made `DELETE`-as-privileged-event but not
        privileged-permission impossible to reintroduce: there is one set now,
        and both sides read it.
        """
        return self.capability.is_privileged


class AuthKind(Enum):
    """
    How a sign-in happened, when the source can tell.

    `login` alone cannot say whether a person or a pipeline authenticated --
    FRESH v3's CI deployer read as "a service account used interactively"
    for exactly that reason. CloudTrail can tell (ConsoleLogin vs an API call
    with keys); many sources cannot. UNKNOWN is the honest default and is
    treated like INTERACTIVE wherever it matters: not knowing must never make
    an identity look safer.
    """

    INTERACTIVE = "interactive"
    PROGRAMMATIC = "programmatic"
    UNKNOWN = "unknown"


_EVENT_CAPABILITIES: dict["EventAction", Capability] = {}


_EVENT_CAPABILITIES.update(
    {
        EventAction.LOGIN: Capability.AUTHENTICATE,
        EventAction.READ: Capability.READ,
        EventAction.WRITE: Capability.WRITE,
        EventAction.DELETE: Capability.DESTROY,
        EventAction.ASSUME_ROLE: Capability.IMPERSONATE,
        EventAction.GRANT_PERMISSION: Capability.MANAGE_PERMISSION,
        EventAction.REVOKE_PERMISSION: Capability.MANAGE_PERMISSION,
    }
)


@dataclass(frozen=True)
class Event:
    """
    One observed action. Frozen and self-validating (2026-10-05); the timestamp
    must be timezone-aware, so a naive time is rejected where it is made
    rather than discovered later inside a time window.
    """

    id: str
    identity_id: str
    resource_id: str
    action: EventAction
    timestamp: datetime
    success: bool
    auth: AuthKind = AuthKind.UNKNOWN

    def __post_init__(self) -> None:
        validate_non_empty_str(self.id, "id")
        validate_non_empty_str(self.identity_id, "identity_id")
        validate_non_empty_str(self.resource_id, "resource_id")
        if not isinstance(self.action, EventAction):
            raise TypeError(f"action must be an EventAction, got {type(self.action).__name__}")
        validate_tz_datetime(self.timestamp, "timestamp")
        if not isinstance(self.success, bool):
            raise TypeError(f"success must be a bool, got {type(self.success).__name__}")
        if not isinstance(self.auth, AuthKind):
            raise TypeError(f"auth must be an AuthKind, got {type(self.auth).__name__}")