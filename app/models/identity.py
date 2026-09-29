from dataclasses import dataclass, field
from enum import Enum

from app.models.permission import Permission
class IdentityType(Enum):
    HUMAN = "human"
    SERVICE = "service"
    AI_agent = "ai_agent"

@dataclass
class Identity:
    id: str
    name: str
    identity_type: IdentityType
    department: str
    # True for guest/B2B accounts, cross-tenant roles and third-party
    # integrations -- principals outside the org's own identity provider.
    # Exposure has an identity side as well as a resource side: access held by
    # someone outside the trust boundary is reachable from outside it.
    is_external: bool = False
    # A designated emergency ("break-glass") account, as tagged by the source
    # of record. Never being used is its *designed* state, so staleness rules
    # skip it; privilege rules never do -- standing admin on a crown jewel is
    # still standing admin, and a tag anyone could set must not be able to
    # hide that. The tag is input, not proof.
    is_break_glass: bool = False
    permissions: list["Permission"] = field(default_factory=list)
