"""
Blast radius: how much a compromise of this identity would reach, as one number
that explains itself.

Built on effective reach, not on grant count. A count cannot see the role an
identity can step into or the ledger its console governs, and it weighs six
reads on dashboards the same as six admin grants on production -- which is why
`read_only_analyst_wide_access` exists.

**Each reachable resource counts once**, at its most dangerous capability
within the cut:

    weight = sensitivity weight x exposure multiplier x capability factor

and the score is the **sum** of weights (see `scoring.py` for why not a
saturating combination). A sum is what makes the number explainable: every
resource has a share, so a finding can say "the ledger is 30 of 41".

**Three cuts, not discounts.** A score is computed up to a `ReachTier`:
STANDING (what ZSP exists to remove), LIVE (anything that works today without
a request -- standing, temporary, and expired-but-attached, since a lingering
expired grant usually means a failed revocation), and POTENTIAL (JIT
included). Discounting JIT by some factor would invent a number nobody could
defend; asking the question at three cuts invents none.

**Unknowns are reported, not weighted.** A resource with no sensitivity (never
observed) or reached only through UNKNOWN capabilities contributes 0 and is
listed, the same convention as everywhere else: counted, never called
critical, and left to coverage to turn into lower confidence.
"""

from dataclasses import dataclass
from typing import Mapping, Optional

from app.graph.effective import EffectiveReach, ReachTier
from app.graph.graph import Edge
from app.graph.reach import hops
from app.models.capability import Capability
from app.models.resource import Exposure, Resource, ResourceType, Sensitivity
from app.risk import scoring

STANDING = ReachTier.STANDING
LIVE = ReachTier.EXPIRED_ATTACHED
POTENTIAL = ReachTier.JIT_ONLY

_READ_CLASS = frozenset({Capability.AUTHENTICATE, Capability.READ})


def capability_factor(capability: Capability, resource: Resource) -> float:
    """What this capability lets an attacker do on this resource. Reads scoring at call time."""
    if capability is Capability.UNKNOWN:
        return 0.0
    if capability.is_privileged:
        return scoring.BLAST_PRIVILEGED_FACTOR
    if capability is Capability.READ and resource.resource_type is ResourceType.SECRET_STORE:
        return scoring.BLAST_PRIVILEGED_FACTOR
    if capability in _READ_CLASS:
        return scoring.BLAST_READ_FACTOR
    return scoring.BLAST_WRITE_FACTOR


def resource_weight(capability: Capability, resource: Resource) -> float:
    return (
        scoring.BLAST_SENSITIVITY_WEIGHT[resource.sensitivity]
        * scoring.BLAST_EXPOSURE_MULTIPLIER[resource.exposure]
        * capability_factor(capability, resource)
    )


@dataclass(frozen=True)
class Contribution:
    """One resource's share of the score, and the path that earns it."""

    resource_id: str
    capability: Capability
    tier: ReachTier
    sensitivity: Sensitivity
    exposure: Exposure
    weight: float
    path: tuple[Edge, ...]

    @property
    def hops(self) -> int:
        return hops(self.path)


@dataclass(frozen=True)
class BlastRadius:
    identity_id: str
    cut: ReachTier
    # Heaviest first, ties by resource id, so the explanation leads with what matters.
    contributions: tuple[Contribution, ...]
    # Reached, but never observed: sensitivity unknown, weight 0.
    unknown_resources: tuple[str, ...]
    # Reached only through capabilities we could not classify: weight 0.
    unclassified_resources: tuple[str, ...]

    @property
    def score(self) -> float:
        return sum(c.weight for c in self.contributions)

    def share(self, resource_id: str) -> float:
        """This resource's fraction of the score (0 when the score is 0)."""
        total = self.score
        if total == 0:
            return 0.0
        return sum(c.weight for c in self.contributions if c.resource_id == resource_id) / total

    def count_at(self, sensitivity: Sensitivity) -> int:
        return sum(1 for c in self.contributions if c.sensitivity is sensitivity)

    @property
    def max_sensitivity(self) -> Optional[Sensitivity]:
        order = list(Sensitivity)
        found = [c.sensitivity for c in self.contributions]
        return max(found, key=order.index) if found else None


def blast_radius(
    reach: EffectiveReach, resources: Mapping[str, Resource], cut: ReachTier
) -> BlastRadius:
    if not isinstance(cut, ReachTier):
        raise TypeError(f"cut must be a ReachTier, got {type(cut).__name__}")

    best: dict[str, Contribution] = {}
    unknown: set[str] = set()
    seen_with_weight: set[str] = set()
    reached: set[str] = set()

    for entry in reach.at_most(cut):
        reached.add(entry.resource_id)
        resource = resources.get(entry.resource_id)
        if resource is None:
            unknown.add(entry.resource_id)
            continue
        weight = resource_weight(entry.capability, resource)
        if weight == 0:
            continue
        seen_with_weight.add(entry.resource_id)
        candidate = Contribution(
            entry.resource_id, entry.capability, entry.tier,
            resource.sensitivity, resource.exposure, weight, entry.path,
        )
        current = best.get(entry.resource_id)
        # Most dangerous capability; then the easier tier, fewer hops, and the
        # capability name, so the chosen path is the same every run.
        if current is None or _rank(candidate) < _rank(current):
            best[entry.resource_id] = candidate

    return BlastRadius(
        identity_id=reach.identity_id,
        cut=cut,
        contributions=tuple(sorted(best.values(), key=lambda c: (-c.weight, c.resource_id))),
        unknown_resources=tuple(sorted(unknown)),
        unclassified_resources=tuple(sorted(reached - unknown - seen_with_weight)),
    )


def _rank(c: Contribution) -> tuple:
    return (-c.weight, c.tier.rank, c.hops, c.capability.value)
