"""
Properties of the graph layer over the whole corpus, and determinism across
processes.

The unit tests pin each behaviour on a hand-built estate. These check that
invariants hold on every identity in the corpus -- the places a hand-built
case would not think to look -- and that nothing depends on Python's
per-process hash seed.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.connectors.synthetic import SyntheticConnector
from app.graph.effective import effective_reach
from app.graph.graph import Edge, EdgeKind, IdentityGraph, NodeRef
from app.graph.reach import active_at, any_grant, describe_path, hops, reach, standing_only
from app.models.capability import Capability
from app.models.permission import Permission
from app.normalize.normalizer import Normalizer
from app.risk import detections
from app.risk.choke_points import find_choke_points
from app.risk.engine import RiskEngine
from tests.test_normalize import ANCHOR

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def estate():
    return Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())


@pytest.fixture(scope="module")
def graph(estate):
    return IdentityGraph.from_estate(estate)


# --- Path explanation ------------------------------------------------------


def test_describe_path_renders_every_kind_of_edge():
    perm = Permission(id="g1", identity_id="a", resource_id="tool", action=Capability.MANAGE_PERMISSION)
    role_perm = Permission(id="g2", identity_id="r", resource_id="db", action=Capability.ADMIN)
    path = (
        Edge(EdgeKind.GRANT, NodeRef.identity("a"), NodeRef.resource("tool"), perm),
        Edge(EdgeKind.GOVERNS, NodeRef.resource("tool"), NodeRef.resource("r_res")),
        Edge(EdgeKind.BECOMES, NodeRef.resource("r_res"), NodeRef.identity("r")),
        Edge(EdgeKind.GRANT, NodeRef.identity("r"), NodeRef.resource("db"), role_perm),
    )
    assert describe_path("a", path) == (
        "a -manage_permission-> tool ~governs~> r_res =becomes=> r -admin-> db"
    )
    assert hops(path) == 3  # becomes is free
    assert describe_path("a", ()) == "a"


def test_every_crown_jewel_route_is_a_contiguous_walk(estate):
    """Each cited route starts at its origin, chains edge to edge, and ends at its target."""
    report = find_choke_points(estate, ANCHOR)
    assert report.routes
    for route in report.routes:
        nodes = [NodeRef.identity(route.origin)]
        for edge in route.path:
            assert edge.source == nodes[-1], (route.pair, edge.edge_id)
            nodes.append(edge.target)
        assert nodes[-1] == NodeRef.resource(route.target)
        assert 2 <= route.hops <= detections.ATTACK_PATH_MAX_HOPS
        assert describe_path(route.origin, route.path).endswith(route.target)


def test_every_finding_cites_evidence_that_exists(estate):
    """A citation that resolves to nothing explains nothing."""
    for result in RiskEngine().assess_estate(estate, ANCHOR):
        for finding in result.assessment.triggered_factors + result.suppressed:
            assert finding.evidence_ids, (result.identity_id, finding.factor_type)
            missing = [e for e in finding.evidence_ids if e not in estate.evidence_by_id]
            assert not missing, (result.identity_id, finding.factor_type, missing)


# --- Monotonicity ----------------------------------------------------------


def pairs(r):
    return {(x.resource_id, x.capability) for x in r.resources}


def test_reach_only_grows_with_the_hop_limit(estate, graph):
    for identity in estate.identities:
        previous = set()
        for k in range(0, 7):
            current = pairs(reach(graph, identity.id, max_hops=k, usable=any_grant))
            assert previous <= current, (identity.id, k)
            previous = current


def test_reach_only_grows_as_the_grant_filter_widens(estate, graph):
    """standing ⊆ active now ⊆ any grant, for every identity."""
    live = active_at(ANCHOR)
    for identity in estate.identities:
        walks = [
            pairs(reach(graph, identity.id, max_hops=8, usable=usable))
            for usable in (standing_only, live, any_grant)
        ]
        assert walks[0] <= walks[1] <= walks[2], identity.id


def test_effective_reach_tiers_never_contradict_a_narrower_walk(estate, graph):
    """Anything reachable with standing grants alone is labelled STANDING, never worse."""
    for identity in estate.identities:
        standing = pairs(reach(graph, identity.id, max_hops=8, usable=standing_only))
        tiered = effective_reach(graph, identity.id, at=ANCHOR, max_hops=8)
        for key in standing:
            assert tiered.get(*key).tier.value == "standing", (identity.id, key)


# --- Determinism across processes ------------------------------------------

_DIGEST = r"""
import hashlib
from datetime import datetime, timezone
from app.connectors.synthetic import SyntheticConnector
from app.normalize.normalizer import Normalizer
from app.risk.engine import RiskEngine
from app.risk.graph_report import format_blast_radius, format_paths
at = datetime(2026, 9, 9, tzinfo=timezone.utc)
estate = Normalizer().normalize(SyntheticConnector(anchor_time=at).collect())
h = hashlib.sha256()
for r in RiskEngine().assess_estate(estate, at):
    for f in r.assessment.triggered_factors + r.suppressed:
        h.update(repr((r.identity_id, f.id, f.description, f.impact, f.likelihood,
                       f.confidence, f.evidence_ids)).encode())
h.update(format_blast_radius(estate, at).encode())
for who in ("petra", "vesna", "gustav", "adaeze"):
    h.update(format_paths(estate, who, at).encode())
print(h.hexdigest())
"""


def _digest(seed: str) -> str:
    env = dict(os.environ, PYTHONHASHSEED=seed)
    out = subprocess.run(
        [sys.executable, "-c", _DIGEST], cwd=REPO, env=env,
        capture_output=True, text=True, check=True, timeout=300,
    )
    return out.stdout.strip()


def test_output_does_not_depend_on_the_hash_seed():
    """
    In-process determinism tests cannot see this: Python randomises string
    hashing per process, so a set's iteration order leaking into a path, a
    tie-break or a report would only differ between runs. Two seeds, one
    answer.
    """
    first = _digest("0")
    assert len(first) == 64
    assert _digest("4242") == first
