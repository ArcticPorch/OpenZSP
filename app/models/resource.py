from dataclasses import dataclass
from enum import Enum
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


@dataclass
class Resource:
    id: str
    name: str
    resource_type: ResourceType
    sensitivity: Sensitivity
    exposure: Exposure = Exposure.INTERNAL

    @property
    def is_externally_exposed(self) -> bool:
        return self.exposure is Exposure.PUBLIC
