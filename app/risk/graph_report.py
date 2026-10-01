"""
Plain-text views of the identity graph, for the CLI.

`--paths <identity>` answers "what can this identity get to, and how?" for one
identity: its routes to crown jewels as readable chains, the roles it can step
into, and its blast radius at each cut. `--blast-radius` answers "who matters
most?" across the estate: identities ranked by standing blast radius, then the
choke points whose removal closes the most crown-jewel routes.

Formatting only. Every number comes from the same functions the rules use
(`effective_reach`, `blast_radius`, `crown_jewel_routes`, `find_choke_points`),
with the engine's own `REACH_MAX_HOPS`, so the report cannot disagree with a
finding.
"""

from datetime import datetime

from app.graph.effective import effective_reach
from app.graph.graph import IdentityGraph
from app.graph.reach import describe_path
from app.risk import detections
from app.risk.blast_radius import LIVE, POTENTIAL, STANDING, blast_radius
from app.risk.choke_points import find_choke_points
from app.risk.engine import is_assessed

TOP_CONTRIBUTIONS = 3


def _hops(n: int) -> str:
    return f"{n} hop" if n == 1 else f"{n} hops"


def format_paths(estate, identity_id: str, at: datetime) -> str:
    """Everything one identity can reach, and how. Raises KeyError for an unknown id."""
    identity = estate.identity(identity_id)
    if identity is None:
        raise KeyError(identity_id)
    graph = IdentityGraph.from_estate(estate)
    resources = {r.id: r for r in estate.resources}
    reach = effective_reach(graph, identity_id, at=at, max_hops=detections.REACH_MAX_HOPS)

    kind = identity.identity_type.value + (", external" if identity.is_external else "")
    lines = [
        f"Reach of {identity_id} ({kind}) at {at.date()}, up to {reach.max_hops} hops",
        "=" * 72,
    ]

    routes = detections.crown_jewel_routes(identity, reach, resources.get, at)
    lines.append("")
    lines.append(f"Routes to crown jewels it holds no grant on ({len(routes)}):")
    if not routes:
        lines.append("  none")
    for target, entry in sorted(routes.items(), key=lambda kv: (kv[1].hops, kv[0])):
        lines.append(
            f"  {target}  [{entry.capability.value}, {_hops(entry.hops)}, {entry.tier.value}]"
        )
        lines.append(f"    {describe_path(identity_id, entry.path)}")

    lines.append("")
    lines.append(f"Principals it can step into ({len(reach.principals)}):")
    if not reach.principals:
        lines.append("  none")
    for p in sorted(reach.principals, key=lambda p: (p.hops, p.identity_id)):
        lines.append(f"  {p.identity_id}  [{_hops(p.hops)}, {p.tier.value}]")

    lines.append("")
    lines.append("Blast radius:")
    for label, cut in (("standing", STANDING), ("live", LIVE), ("potential", POTENTIAL)):
        radius = blast_radius(reach, resources, cut)
        lines.append(
            f"  {label:<10}{radius.score:7.1f}  over {len(radius.contributions)} resource(s)"
        )
    standing = blast_radius(reach, resources, STANDING)
    for c in standing.contributions:
        lines.append(
            f"    {c.resource_id:<32} {c.sensitivity.value:<9} {c.capability.value:<18}"
            f"{c.weight:6.1f}  ({standing.share(c.resource_id):.0%}, {_hops(c.hops)})"
        )
    if standing.stepping_stones:
        lines.append(f"    stepping-stones (not counted): {', '.join(standing.stepping_stones)}")
    if standing.unknown_resources:
        lines.append(f"    never observed (weight 0): {', '.join(standing.unknown_resources)}")
    if standing.unclassified_resources:
        lines.append(
            f"    unclassified capability (weight 0): {', '.join(standing.unclassified_resources)}"
        )

    truncated = ", ".join(t.value for t in reach.truncated)
    if truncated:
        lines.append("")
        lines.append(f"Hop limit reached with edges left to follow ({truncated}): reach is a lower bound.")
    return "\n".join(lines)


def format_blast_radius(estate, at: datetime, top: int = 15) -> str:
    """Identities ranked by standing blast radius, then the estate's choke points."""
    graph = IdentityGraph.from_estate(estate)
    resources = {r.id: r for r in estate.resources}
    rows = []
    for identity in estate.identities:
        if not is_assessed(identity):
            continue
        reach = effective_reach(graph, identity.id, at=at, max_hops=detections.REACH_MAX_HOPS)
        cuts = [blast_radius(reach, resources, cut) for cut in (STANDING, LIVE, POTENTIAL)]
        if cuts[-1].score == 0:
            continue
        rows.append((identity.id, cuts))
    rows.sort(key=lambda row: (-row[1][0].score, -row[1][2].score, row[0]))

    lines = [
        f"Blast radius at {at.date()} (top {min(top, len(rows))} of {len(rows)} identities with any reach)",
        "=" * 72,
        f"  {'identity':<26}{'standing':>9}{'live':>8}{'potential':>10}  heaviest standing resources",
    ]
    for identity_id, (standing, live, potential) in rows[:top]:
        heaviest = ", ".join(
            f"{c.resource_id} {c.weight:.1f}" for c in standing.contributions[:TOP_CONTRIBUTIONS]
        )
        lines.append(
            f"  {identity_id:<26}{standing.score:9.1f}{live.score:8.1f}{potential.score:10.1f}"
            f"  {heaviest or '-'}"
        )

    report = find_choke_points(estate, at)
    lines += [
        "",
        f"Choke points: single links whose removal cuts the most of the "
        f"{len(report.routes)} crown-jewel routes",
        "=" * 72,
    ]
    if not report.choke_points:
        lines.append("  none")
    for point in report.choke_points[:top]:
        pairs = ", ".join(f"{origin} -> {target}" for origin, target in point.cuts)
        lines.append(f"  {point.edge_id:<44} {point.kind.value:<8} cuts {len(point.cuts)}: {pairs}")
    if report.uncut:
        lines.append("")
        lines.append("Routes no single link closes (two or more independent paths):")
        for origin, target in report.uncut:
            lines.append(f"  {origin} -> {target}")
    return "\n".join(lines)
