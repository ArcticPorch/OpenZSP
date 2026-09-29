"""
Cross-identity baselines: the one place the engine looks across identities.

Rules are deliberately O(1) in the size of the estate -- `RuleContext` carries
one identity, never the `Estate` -- because a rule that can reach every other
identity grows cross-identity logic nobody can reason about. Peer comparison
genuinely needs the whole estate, so it is computed **once, before any rule
runs**, into an immutable summary the rules can read by key. Rules stay O(1);
the pre-pass is O(grants).

Like `IdentityFeatures` and `CoverageSummary`, a baseline is interpretation-free:
it holds *who holds what*, never a judgement about whether that is unusual. How
rare is too rare is a threshold, and thresholds live in `detections.py`.

**Why the peer group is built from the resource's side.** The obvious baseline
is department-centric ("17 of 18 people in Marketing don't have this"). But a
department is a free-text attribute that scenarios -- and real HR feeds -- share
by coincidence, so a department-wide statistic changes whenever any unrelated
identity joins or leaves. That breaks a property this project leans on:
evaluating one split must give the same answer that split gives inside the full
corpus. The resource-centric question -- "the other people who hold access to
*this* resource: are any of them in your department?" -- only depends on the
holders of one resource, which is stable, and is also the more explainable
finding: "four people hold the payments ledger; all four are in Finance; you
are in Marketing".
"""

from dataclasses import dataclass
from typing import Iterable, Optional

from app.models.identity import Identity


@dataclass(frozen=True)
class PeerBaseline:
    """
    For every resource, who holds a grant on it and which department they are in.

    `holders` maps resource id -> ((identity_id, department), ...), sorted so two
    builds over the same estate are equal. Every lifecycle counts as holding:
    a JIT-eligible Finance analyst is still evidence that the ledger belongs to
    Finance.
    """

    holders: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = ()

    @classmethod
    def build(cls, identities: Iterable[Identity]) -> "PeerBaseline":
        by_resource: dict[str, set[tuple[str, str]]] = {}
        for identity in identities:
            for perm in identity.permissions:
                by_resource.setdefault(perm.resource_id, set()).add(
                    (identity.id, identity.department)
                )
        return cls(
            holders=tuple(
                sorted((rid, tuple(sorted(members))) for rid, members in by_resource.items())
            )
        )

    def other_holders(
        self, resource_id: str, identity_id: str
    ) -> tuple[tuple[str, str], ...]:
        """(identity_id, department) of everyone else holding this resource."""
        members = self._lookup().get(resource_id, ())
        return tuple(m for m in members if m[0] != identity_id)

    def _lookup(self) -> dict[str, tuple[tuple[str, str], ...]]:
        # Frozen dataclass: cache the dict view on first use without mutating
        # any declared field, so equality and hashing stay content-based.
        cached: Optional[dict] = self.__dict__.get("_index")
        if cached is None:
            cached = dict(self.holders)
            object.__setattr__(self, "_index", cached)
        return cached
