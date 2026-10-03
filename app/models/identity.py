from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from app.models.permission import Permission
class IdentityType(Enum):
    HUMAN = "human"
    SERVICE = "service"
    AI_agent = "ai_agent"
    # A principal nobody logs in as: it is only ever *become*, by impersonating
    # the resource that points at it (`Resource.principal_id`). It holds grants
    # like any identity, which is what makes access paths multi-hop.
    ROLE = "role"

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
    # Where the identity sits in the organisation, as an HR feed supplies it:
    # "Finance/Treasury". Optional; without it the flat department is all we
    # know. Departments are free text, so "Treasury" and "Accounts Payable"
    # look unrelated -- the path says they are both Finance.
    org_path: Optional[str] = None

    @property
    def org_family(self) -> str:
        """The top-level org unit, or the department when no path is known."""
        if self.org_path:
            return self.org_path.split("/", 1)[0].strip()
        return self.department
