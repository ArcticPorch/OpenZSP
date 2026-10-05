"""
Reachability: everything an identity can get to, and one path to each.

Starting from an identity, the walk follows usable grants to resources,
records every (resource, capability) it lands on, and keeps going wherever the
capability opens a door (`semantics.py`):

* an assuming capability on a role's resource steps into the role, whose own
  grants are then followed;
* a managing capability on a control plane spreads to every resource it
  governs, with every capability -- the holder can grant itself anything.

**A hop is one grant or governs edge.** Crossing `becomes` is free: a role's
resource and its principal are two sides of one role, so stepping through a
role costs two hops (the grant onto it, the role's own grant), and the hop
count reads as "how many permissions were chained".

**One shortest path per result.** The walk goes level by level, so the first
time a (resource, capability) is reached is by a fewest-hops path, and edges
are visited in sorted order, so ties break the same way every run. The path is
the explanation a finding cites. Keeping every path would grow exponentially
with the estate while a finding shows one anyway.

**Which grants count is the caller's decision** (`usable`). The graph holds
every grant; standing-only, active-at-t and any-grant are three answers to
three different questions, and conflating them is how "reachable" silently
starts meaning "reachable if someone approves a JIT request".

**`truncated` says whether the hop limit stopped the walk** with edges still to
follow. A reach that ended because nothing was left and one that ended because
we stopped looking are different claims, the same distinction coverage makes
between "nothing to see" and "we cannot see".
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from app.common.validation import validate_tz_datetime
from app.graph.graph import Edge, EdgeKind, IdentityGraph, NodeKind, NodeRef
from app.graph.semantics import (
    ALL_CAPABILITIES,
    can_assume,
    effective_capabilities,
    manages_permission,
)
from app.models.capability import Capability
from app.models.permission import Permission

UsableGrant = Callable[[Permission], bool]


def any_grant(_: Permission) -> bool:
    """Every grant, including JIT-eligible and expired: the widest question."""
    return True


def standing_only(permission: Permission) -> bool:
    """Always-on grants: what an attacker holding this identity gets with no request."""
    return permission.is_standing


def active_at(evaluation_time: datetime) -> UsableGrant:
    """Grants conferring access at `evaluation_time` without a request."""
    validate_tz_datetime(evaluation_time, "evaluation_time")
    return lambda permission: permission.confers_access_at(evaluation_time)


def hops(path: tuple[Edge, ...]) -> int:
    return sum(1 for edge in path if edge.kind is not EdgeKind.BECOMES)


def describe_path(origin: str, path: tuple[Edge, ...], label=lambda node_id: node_id) -> str:
    """
    A path as a reader follows it: who, which grant, which step, where.

        petra -impersonate-> helpdesk_tier2_role =becomes=> role_helpdesk_tier2 -admin-> support_crm_db

    `label` renders an id for display (the CLI shortens AWS ARNs); it never
    changes what the path is.
    """
    out = [label(origin)]
    for edge in path:
        out.append(f"{_arrow(edge)} {label(edge.target.id)}")
    return " ".join(out)


def describe_edge(edge: Edge, label=lambda node_id: node_id) -> str:
    """One edge as a reader would say it: `alice -impersonate-> deploy_role`."""
    return f"{label(edge.source.id)} {_arrow(edge)} {label(edge.target.id)}"


def _arrow(edge: Edge) -> str:
    if edge.kind is EdgeKind.GRANT:
        return f"-{edge.permission.action.value}->"
    if edge.kind is EdgeKind.BECOMES:
        return "=becomes=>"
    return "~governs~>"


@dataclass(frozen=True)
class Reached:
    """A (resource, capability) the origin can get to, and the path that gets there."""

    resource_id: str
    capability: Capability
    path: tuple[Edge, ...]

    def __post_init__(self) -> None:
        if not self.path or self.path[-1].target != NodeRef.resource(self.resource_id):
            raise ValueError("a path must end at the reached resource")

    @property
    def hops(self) -> int:
        return hops(self.path)


@dataclass(frozen=True)
class Became:
    """A principal the origin can step into, and how."""

    identity_id: str
    path: tuple[Edge, ...]

    def __post_init__(self) -> None:
        if not self.path or self.path[-1].target != NodeRef.identity(self.identity_id):
            raise ValueError("a path must end at the principal")

    @property
    def hops(self) -> int:
        return hops(self.path)


@dataclass(frozen=True)
class Reach:
    origin: str
    max_hops: int
    resources: tuple[Reached, ...]
    principals: tuple[Became, ...]
    truncated: bool
    _index: dict[tuple[str, Capability], Reached] = field(
        default_factory=dict, repr=False, compare=False
    )

    def get(self, resource_id: str, capability: Capability) -> Optional[Reached]:
        return self._index.get((resource_id, capability))

    def resource_ids(self) -> tuple[str, ...]:
        return tuple(sorted({r.resource_id for r in self.resources}))


@dataclass(frozen=True)
class _Step:
    node: NodeRef
    path: tuple[Edge, ...]
    # Set when arriving at a resource: what the path confers there.
    capabilities: frozenset[Capability] = frozenset()


def reach(
    graph: IdentityGraph,
    identity_id: str,
    *,
    max_hops: int,
    usable: UsableGrant,
    blocked: frozenset[str] = frozenset(),
) -> Reach:
    """
    `blocked` names edges (by `edge_id`) the walk must not use -- the "what if
    this link were gone?" question choke-point analysis asks.
    """
    if isinstance(max_hops, bool) or not isinstance(max_hops, int):
        raise TypeError(f"max_hops must be an int, got {type(max_hops).__name__}")
    if max_hops < 0:
        raise ValueError(f"max_hops must be >= 0, got {max_hops}")

    origin = NodeRef.identity(identity_id)
    reached: dict[tuple[str, Capability], Reached] = {}
    became: dict[str, Became] = {}
    entered: set[NodeRef] = {origin}
    managed: set[NodeRef] = set()
    truncated = False

    # levels[d] holds the steps whose path is d hops long. Stepping into a
    # principal is free, so it joins the level being processed.
    levels: list[list[_Step]] = [[] for _ in range(max_hops + 1)]
    levels[0].append(_Step(origin, ()))

    for depth, level in enumerate(levels):
        i = 0
        while i < len(level):
            step = level[i]
            i += 1

            if step.node.kind is NodeKind.IDENTITY:
                for edge in graph.out_edges(step.node):
                    if edge.kind is not EdgeKind.GRANT or not usable(edge.permission):
                        continue
                    if edge.edge_id in blocked:
                        continue
                    if depth == max_hops:
                        truncated = True
                        continue
                    levels[depth + 1].append(
                        _Step(
                            edge.target,
                            step.path + (edge,),
                            effective_capabilities(edge.permission.action),
                        )
                    )
                continue

            # Arrived at a resource.
            for cap in sorted(step.capabilities, key=lambda c: c.value):
                key = (step.node.id, cap)
                if key not in reached:
                    reached[key] = Reached(step.node.id, cap, step.path)

            if any(can_assume(c) for c in step.capabilities):
                for edge in graph.out_edges(step.node):
                    if (
                        edge.kind is EdgeKind.BECOMES
                        and edge.target not in entered
                        and edge.edge_id not in blocked
                    ):
                        entered.add(edge.target)
                        path = step.path + (edge,)
                        became[edge.target.id] = Became(edge.target.id, path)
                        level.append(_Step(edge.target, path))

            if any(manages_permission(c) for c in step.capabilities) and step.node not in managed:
                managed.add(step.node)
                for edge in graph.out_edges(step.node):
                    if edge.kind is not EdgeKind.GOVERNS or edge.edge_id in blocked:
                        continue
                    if depth == max_hops:
                        truncated = True
                        continue
                    levels[depth + 1].append(
                        _Step(edge.target, step.path + (edge,), ALL_CAPABILITIES)
                    )

    ordered = tuple(sorted(reached.values(), key=lambda r: (r.resource_id, r.capability.value)))
    return Reach(
        origin=identity_id,
        max_hops=max_hops,
        resources=ordered,
        principals=tuple(became[k] for k in sorted(became)),
        truncated=truncated,
        _index=dict(reached),
    )
