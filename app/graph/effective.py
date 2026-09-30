"""
Effective reach: what an identity can get to, and how easily.

`reach()` answers one question with one grant filter. Effective reach asks it
four times with nested filters and labels each (resource, capability) with the
*easiest* tier that gets there:

  STANDING          always-on grants all the way. Nothing has to happen.
  TEMPORARY         needs a time-bound or elevated grant that is live now.
                    Works today; stops on its own.
  EXPIRED_ATTACHED  needs a grant past its expiry that is still in the estate.
                    Works only if a revocation failed -- which is what a
                    lingering expired grant usually means.
  JIT_ONLY          needs something that has not happened: a JIT request
                    approved, or a scheduled grant's window opening.

The order is how much has to go right for an attacker holding this identity.
A path's tier is its **weakest link**: one JIT hop makes the whole path JIT.
Tier beats length -- a five-hop standing path is kept over a two-hop JIT one,
because the standing one needs nobody's approval.

Why four and not "standing vs JIT": a four-hour elevation and always-on admin
are exactly the difference a zero-standing-privilege engine exists to measure,
and an expired grant still attached is neither -- filing it under JIT would
read a failed revocation as "needs approval", an understatement.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from app.common.validation import validate_tz_datetime
from app.graph.graph import Edge, IdentityGraph
from app.graph.reach import hops, reach
from app.models.capability import Capability
from app.models.permission import Permission


class ReachTier(Enum):
    STANDING = "standing"
    TEMPORARY = "temporary"
    EXPIRED_ATTACHED = "expired_attached"
    JIT_ONLY = "jit_only"

    @property
    def rank(self) -> int:
        return _TIER_ORDER.index(self)


_TIER_ORDER: tuple[ReachTier, ...] = tuple(ReachTier)


def grant_tier(permission: Permission, at: datetime) -> ReachTier:
    """The easiest tier at which this one grant is usable at `at`."""
    if permission.is_standing:
        return ReachTier.STANDING
    if permission.confers_access_at(at):
        return ReachTier.TEMPORARY
    if permission.is_expired_at(at):
        return ReachTier.EXPIRED_ATTACHED
    return ReachTier.JIT_ONLY


@dataclass(frozen=True)
class TieredReach:
    resource_id: str
    capability: Capability
    tier: ReachTier
    path: tuple[Edge, ...]

    @property
    def hops(self) -> int:
        return hops(self.path)


@dataclass(frozen=True)
class TieredPrincipal:
    identity_id: str
    tier: ReachTier
    path: tuple[Edge, ...]

    @property
    def hops(self) -> int:
        return hops(self.path)


@dataclass(frozen=True)
class EffectiveReach:
    identity_id: str
    evaluation_time: datetime
    max_hops: int
    entries: tuple[TieredReach, ...]
    principals: tuple[TieredPrincipal, ...]
    # Tiers whose walk the hop limit cut short. Per tier, because a wider
    # filter can reach the same ground in fewer hops.
    truncated: tuple[ReachTier, ...]
    _index: dict[tuple[str, Capability], TieredReach] = field(
        default_factory=dict, repr=False, compare=False
    )

    def get(self, resource_id: str, capability: Capability) -> Optional[TieredReach]:
        return self._index.get((resource_id, capability))

    def at_most(self, tier: ReachTier) -> tuple[TieredReach, ...]:
        """Everything reachable at this tier or an easier one."""
        return tuple(e for e in self.entries if e.tier.rank <= tier.rank)

    def resource_ids(self, tier: ReachTier = ReachTier.JIT_ONLY) -> tuple[str, ...]:
        return tuple(sorted({e.resource_id for e in self.at_most(tier)}))


def effective_reach(
    graph: IdentityGraph, identity_id: str, *, at: datetime, max_hops: int
) -> EffectiveReach:
    validate_tz_datetime(at, "at")
    entries: dict[tuple[str, Capability], TieredReach] = {}
    principals: dict[str, TieredPrincipal] = {}
    truncated: list[ReachTier] = []

    for tier in _TIER_ORDER:
        walk = reach(
            graph,
            identity_id,
            max_hops=max_hops,
            usable=lambda p, tier=tier: grant_tier(p, at).rank <= tier.rank,
        )
        if walk.truncated:
            truncated.append(tier)
        # Easier tiers ran first, so the first tier to reach a key is its tier.
        for r in walk.resources:
            key = (r.resource_id, r.capability)
            if key not in entries:
                entries[key] = TieredReach(r.resource_id, r.capability, tier, r.path)
        for b in walk.principals:
            if b.identity_id not in principals:
                principals[b.identity_id] = TieredPrincipal(b.identity_id, tier, b.path)

    return EffectiveReach(
        identity_id=identity_id,
        evaluation_time=at,
        max_hops=max_hops,
        entries=tuple(entries[k] for k in sorted(entries, key=lambda k: (k[0], k[1].value))),
        principals=tuple(principals[k] for k in sorted(principals)),
        truncated=tuple(truncated),
        _index=dict(entries),
    )
