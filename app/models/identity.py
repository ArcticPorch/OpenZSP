from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.common.validation import validate_non_empty_str
from app.models.permission import Permission


class IdentityType(Enum):
    HUMAN = "human"
    SERVICE = "service"
    AI_agent = "ai_agent"
    # A principal nobody logs in as: it is only ever *become*, by impersonating
    # the resource that points at it (`Resource.principal_id`). It holds grants
    # like any identity, which is what makes access paths multi-hop.
    ROLE = "role"


def _validate_bool(val, name: str) -> None:
    if not isinstance(val, bool):
        raise TypeError(f"{name} must be a bool, got {type(val).__name__}")


def _validate_optional_str(val, name: str) -> None:
    if val is not None:
        validate_non_empty_str(val, name)


@dataclass(frozen=True)
class Identity:
    """
    A principal, as one source of record describes it.

    Frozen and self-validating, like `Permission` (2026-10-05): every field is
    checked on construction, and `permissions` is a tuple. A domain object an
    analysis could mutate mid-run is one whose findings cannot be reproduced.
    """

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
    # Any sequence is accepted and stored as a tuple, so the identity is
    # immutable and hashable like the rest of the domain.
    permissions: tuple[Permission, ...] = ()
    # Where the identity sits in the organisation, as an HR feed supplies it:
    # "Finance/Treasury". Optional; without it the flat department is all we
    # know. Departments are free text, so "Treasury" and "Accounts Payable"
    # look unrelated -- the path says they are both Finance.
    org_path: Optional[str] = None

    def __post_init__(self) -> None:
        validate_non_empty_str(self.id, "id")
        validate_non_empty_str(self.name, "name")
        if not isinstance(self.identity_type, IdentityType):
            raise TypeError(
                f"identity_type must be an IdentityType, got {type(self.identity_type).__name__}"
            )
        validate_non_empty_str(self.department, "department")
        _validate_bool(self.is_external, "is_external")
        _validate_bool(self.is_break_glass, "is_break_glass")
        _validate_optional_str(self.org_path, "org_path")
        if not isinstance(self.permissions, (list, tuple)):
            raise TypeError(
                f"permissions must be a sequence, got {type(self.permissions).__name__}"
            )
        perms = tuple(self.permissions)
        for perm in perms:
            if not isinstance(perm, Permission):
                raise TypeError(f"permissions must hold Permission, got {type(perm).__name__}")
            if perm.identity_id != self.id:
                raise ValueError(f"grant {perm.id} belongs to '{perm.identity_id}', not '{self.id}'")
        object.__setattr__(self, "permissions", perms)

    @property
    def org_family(self) -> str:
        """The top-level org unit, or the department when no path is known."""
        if self.org_path:
            return self.org_path.split("/", 1)[0].strip()
        return self.department
