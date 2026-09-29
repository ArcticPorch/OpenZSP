"""
Building the identity-resource graph.

Structure only: which nodes and edges exist, and that building is deterministic.
Traversal is tested with the reachability layer.
"""

from datetime import timedelta

import pytest

from app.connectors.synthetic import SyntheticConnector
from app.graph.graph import Edge, EdgeKind, IdentityGraph, NodeKind, NodeRef
from app.models.capability import Capability
from app.models.permission import GrantLifecycle, Permission
from app.normalize.normalizer import Normalizer
from tests.test_normalize import ANCHOR, grant_ev, identity_ev, normalize, resource_ev
from tests.test_roles import role_estate

I, R = NodeRef.identity, NodeRef.resource


def shape(graph: IdentityGraph) -> list[tuple[str, str, str, str]]:
    return [(e.source.id, e.kind.value, e.target.id, e.edge_id) for e in graph.edges]


def test_role_chain_becomes_three_edges():
    graph = IdentityGraph.from_estate(role_estate())
    assert shape(graph) == [
        ("irene", "grant", "finance_admin_role", "g_irene_role"),
        ("role_finance_admin", "grant", "ledger", "g_role_ledger"),
        ("finance_admin_role", "becomes", "role_finance_admin", "becomes:finance_admin_role"),
    ]
    assert set(graph.nodes) == {
        I("irene"), I("role_finance_admin"), R("finance_admin_role"), R("ledger")
    }


def test_edges_carry_the_permission_itself():
    estate = role_estate()
    [edge] = IdentityGraph.from_estate(estate).out_edges(I("irene"))
    assert edge.permission is estate.identity("irene").permissions[0]
    assert edge.permission.action is Capability.IMPERSONATE


def test_identity_and_resource_with_the_same_id_stay_separate():
    """Keyed by (kind, id): a shared name must not invent an access path."""
    graph = IdentityGraph.from_estate(
        normalize([identity_ev("payroll"), resource_ev("payroll")])
    )
    assert graph.nodes == (I("payroll"), R("payroll"))
    assert graph.edges == ()


# --- Nothing is filtered at build time -------------------------------------


def test_jit_and_expired_grants_are_edges():
    """Whether an edge counts at time t is traversal's call, not the builder's."""
    estate = normalize(
        [
            identity_ev(),
            resource_ev(),
            grant_ev("g_jit", payload={"lifecycle": "jit_eligible"}),
            grant_ev(
                "g_expired",
                payload={
                    "lifecycle": "time_bound",
                    "expires_at": (ANCHOR - timedelta(days=30)).isoformat(),
                },
            ),
        ]
    )
    graph = IdentityGraph.from_estate(estate)
    lifecycles = {e.edge_id: e.permission.lifecycle for e in graph.edges}
    assert lifecycles == {
        "g_jit": GrantLifecycle.JIT_ELIGIBLE,
        "g_expired": GrantLifecycle.TIME_BOUND,
    }


def test_dangling_references_become_bare_nodes():
    """Understating reach is the one direction we must not err in."""
    estate = normalize(
        [
            identity_ev(),
            grant_ev(resource_id="ghost_db"),
            resource_ev("orphan_role", payload={"principal_id": "ghost_role"}),
        ]
    )
    graph = IdentityGraph.from_estate(estate)
    assert R("ghost_db") in graph.nodes and graph.is_bare(R("ghost_db"))
    assert I("ghost_role") in graph.nodes and graph.is_bare(I("ghost_role"))
    assert graph.resource("ghost_db") is None
    assert graph.identity("ghost_role") is None
    assert not graph.is_bare(I("alice"))


# --- Determinism -----------------------------------------------------------


def test_build_is_independent_of_input_order():
    estate = role_estate()
    forward = IdentityGraph.build(estate.identities, estate.resources)
    backward = IdentityGraph.build(reversed(estate.identities), reversed(estate.resources))
    assert forward == backward
    assert shape(forward) == shape(backward)


def test_out_edges_of_an_unknown_node_is_empty():
    assert IdentityGraph.from_estate(role_estate()).out_edges(I("nobody")) == ()


def test_duplicate_ids_are_rejected():
    estate = role_estate()
    with pytest.raises(ValueError, match="duplicate identity"):
        IdentityGraph.build(estate.identities * 2, estate.resources)


# --- Edge invariants -------------------------------------------------------


def perm(**over) -> Permission:
    fields = dict(id="g", identity_id="a", resource_id="r", action=Capability.READ)
    fields.update(over)
    return Permission(**fields)


def test_grant_edge_requires_its_permission():
    with pytest.raises(TypeError):
        Edge(EdgeKind.GRANT, I("a"), R("r"))


def test_grant_edge_must_match_its_permission():
    with pytest.raises(ValueError):
        Edge(EdgeKind.GRANT, I("someone_else"), R("r"), perm())
    with pytest.raises(ValueError):
        Edge(EdgeKind.GRANT, I("a"), R("elsewhere"), perm())


def test_becomes_edge_runs_resource_to_identity_without_a_permission():
    with pytest.raises(ValueError):
        Edge(EdgeKind.BECOMES, R("r"), I("a"), perm())
    with pytest.raises(ValueError):
        Edge(EdgeKind.BECOMES, I("a"), R("r"))


def test_node_ref_rejects_bad_input():
    with pytest.raises(TypeError):
        NodeRef("identity", "a")
    with pytest.raises(ValueError):
        NodeRef(NodeKind.IDENTITY, " ")


# --- The whole corpus ------------------------------------------------------


def test_every_corpus_grant_is_exactly_one_edge():
    estate = Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    graph = IdentityGraph.from_estate(estate)

    grants = sorted(p.id for i in estate.identities for p in i.permissions)
    grant_edges = sorted(e.edge_id for e in graph.edges if e.kind is EdgeKind.GRANT)
    assert grant_edges == grants

    becomes = [e for e in graph.edges if e.kind is EdgeKind.BECOMES]
    assert len(becomes) == sum(1 for r in estate.resources if r.is_assumable)

    # Edge ids are unique, so a path can cite them and a choke point can name one.
    assert len({e.edge_id for e in graph.edges}) == len(graph.edges)
