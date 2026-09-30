"""
Choke points: the single links whose removal cuts the most routes to crown jewels.

Detection says "petra can reach the customer database". Remediation needs a
different answer: *which one change* closes the most of those routes at once.
A role's grant shared by forty contractors is one change that closes forty
routes; revoking each contractor's hop is forty changes.

**The routes** are every indirect live route to control of a CRITICAL resource
(`detections.crown_jewel_routes`) -- the attack-path rule's targets *and* the
standing permission-management routes it hands to
`standing_permission_management.v2`. Detection reports each situation once;
remediation needs every route, whichever rule reported it.

**"Cuts" is verified, never inferred.** Reach keeps one path per target, and an
edge on that path may have a bypass. Counting appearances would advise a
remediation that changes nothing. So each candidate edge is removed and the
affected origins are walked again; a route counts as cut only if no qualifying
route to that target remains. A route with two independent paths has no single
choke point, and is reported as such (`uncut`) rather than hidden.

Estate-level and advisory: this is not a rule and never fires a finding. It is
computed on demand, the same walk the engine does, with a link blocked.
"""

from dataclasses import dataclass
from datetime import datetime

from app.common.validation import validate_tz_datetime
from app.graph.effective import EffectiveReach, ReachTier, effective_reach
from app.graph.graph import Edge, EdgeKind, IdentityGraph
from app.graph.reach import hops
from app.risk import detections
from app.risk.engine import is_assessed


@dataclass(frozen=True)
class Route:
    """One origin's route to control of one crown jewel."""

    origin: str
    target: str
    tier: ReachTier
    path: tuple[Edge, ...]

    @property
    def hops(self) -> int:
        return hops(self.path)

    @property
    def pair(self) -> tuple[str, str]:
        return (self.origin, self.target)


@dataclass(frozen=True)
class ChokePoint:
    edge: Edge
    # (origin, target) pairs that lose every qualifying route without this edge.
    cuts: tuple[tuple[str, str], ...]

    @property
    def edge_id(self) -> str:
        return self.edge.edge_id

    @property
    def kind(self) -> EdgeKind:
        return self.edge.kind


@dataclass(frozen=True)
class ChokePointReport:
    routes: tuple[Route, ...]
    # Most routes cut first, ties by edge id. Only edges that cut something.
    choke_points: tuple[ChokePoint, ...]
    # Pairs no single link cuts: two or more independent routes.
    uncut: tuple[tuple[str, str], ...]


def find_choke_points(estate, at: datetime) -> ChokePointReport:
    """`estate` is anything with `identities` and `resources`, like `Estate`."""
    validate_tz_datetime(at, "at")
    graph = IdentityGraph.from_estate(estate)
    resources = {r.id: r for r in estate.resources}
    origins = {i.id: i for i in estate.identities if is_assessed(i)}

    def routes_of(identity_id: str, blocked: frozenset[str]) -> dict:
        reach = _reach(graph, identity_id, at, blocked)
        return detections.crown_jewel_routes(origins[identity_id], reach, resources.get, at)

    routes = tuple(
        Route(origin, target, entry.tier, entry.path)
        for origin in sorted(origins)
        for target, entry in sorted(routes_of(origin, frozenset()).items())
    )

    # Candidates: every edge on some route. An edge on no kept path cannot cut
    # anything -- the kept path survives its removal.
    using: dict[str, list[Route]] = {}
    edges: dict[str, Edge] = {}
    for route in routes:
        for edge in route.path:
            using.setdefault(edge.edge_id, []).append(route)
            edges[edge.edge_id] = edge

    points = []
    for edge_id in sorted(using):
        blocked = frozenset({edge_id})
        cut = []
        for origin in sorted({r.origin for r in using[edge_id]}):
            remaining = routes_of(origin, blocked)
            cut.extend(r.pair for r in using[edge_id] if r.origin == origin and r.target not in remaining)
        if cut:
            points.append(ChokePoint(edges[edge_id], tuple(sorted(cut))))

    points.sort(key=lambda p: (-len(p.cuts), p.edge_id))
    cut_pairs = {pair for p in points for pair in p.cuts}
    return ChokePointReport(
        routes=routes,
        choke_points=tuple(points),
        uncut=tuple(sorted(r.pair for r in routes if r.pair not in cut_pairs)),
    )


def _reach(graph: IdentityGraph, identity_id: str, at: datetime, blocked) -> EffectiveReach:
    # Read at call time, like the engine, so a sweep override applies here too.
    return effective_reach(
        graph, identity_id, at=at, max_hops=detections.REACH_MAX_HOPS, blocked=blocked
    )
