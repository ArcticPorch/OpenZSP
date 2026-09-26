from dataclasses import dataclass
from datetime import datetime
from enum import Enum

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


@dataclass
class Event:
    id: str
    identity_id: str
    resource_id: str
    action: EventAction
    timestamp: datetime
    success: bool