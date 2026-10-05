from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.common.validation import validate_non_empty_str


class ResourceType(Enum):
    DATABASE = "database"
    REPOSITORY = "repository"
    CLOUD_ACCOUNT = "cloud_account"
    SERVER = "server"
    API = "api"
    # Vaults, secret managers, KMS/HSM key stores. Singled out because READ on
    # one is not ordinary read: a secret is someone else's access, so reading
    # it confers whatever that credential confers.
    SECRET_STORE = "secret_store"


class Exposure(Enum):
    """
    How reachable a resource is from outside the trust boundary.

    Separate from `Sensitivity` because they answer different questions and the
    risk is their *product*, not either alone. A public marketing site is
    exposed and worthless; an internal payments ledger is priceless and
    unreachable. Neither is urgent. Standing admin on something both critical
    and public is the combination that gets someone paged, and collapsing the
    two axes into one "risk level" makes that combination unexpressible.

    Defaults to INTERNAL: a resource we have no exposure evidence for is
    assumed unreachable rather than public, because the alternative floods the
    output with speculative findings on every unenriched resource. The cost is
    that missing Access Analyzer data reads as safe -- which is why coverage
    tracks completeness separately.
    """

    INTERNAL = "internal"      # private network only
    VPC_PEERED = "vpc_peered"  # reachable from partner or peered networks
    PUBLIC = "public"          # internet-facing


class Sensitivity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Resource:
    """A thing access is granted on. Frozen and self-validating (2026-10-05)."""

    id: str
    name: str
    resource_type: ResourceType
    sensitivity: Sensitivity
    exposure: Exposure = Exposure.INTERNAL
    # Set when this resource is also a principal: impersonating it makes you
    # the identity named here, and you inherit that identity's grants. A role
    # has two sides -- something you are granted (this resource) and something
    # that holds grants (that identity) -- and this pointer is the only thing
    # joining them. Explicit rather than a shared id, because two ids that
    # happen to match must not invent an access path.
    principal_id: Optional[str] = None
    # Set when this resource is a control plane: holding permission management
    # on it means being able to grant yourself anything on each resource listed
    # here. A grant only names the resource it sits on, so without this an IAM
    # console rated MEDIUM hides the CRITICAL ledger it controls. Explicit for
    # the same reason as `principal_id`: scope is data from the source, never
    # guessed -- guessing "everything" gives every IAM admin the same maximal
    # reach and makes reach useless for ranking.
    governs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_non_empty_str(self.id, "id")
        validate_non_empty_str(self.name, "name")
        for value, enum_cls, name in (
            (self.resource_type, ResourceType, "resource_type"),
            (self.sensitivity, Sensitivity, "sensitivity"),
            (self.exposure, Exposure, "exposure"),
        ):
            if not isinstance(value, enum_cls):
                raise TypeError(f"{name} must be a {enum_cls.__name__}, got {type(value).__name__}")
        if self.principal_id is not None:
            validate_non_empty_str(self.principal_id, "principal_id")
        if not isinstance(self.governs, (list, tuple)):
            raise TypeError(f"governs must be a sequence, got {type(self.governs).__name__}")
        governs = tuple(self.governs)
        for governed in governs:
            validate_non_empty_str(governed, "governs[]")
        object.__setattr__(self, "governs", governs)

    @property
    def is_assumable(self) -> bool:
        return self.principal_id is not None

    @property
    def is_externally_exposed(self) -> bool:
        return self.exposure is Exposure.PUBLIC
