"""
Edge types: what a grant edge means for reach.

Each meaning is stated per capability, so these tests pin the capability
table as well as the per-edge classification built on it.
"""

import pytest

from app.graph.graph import EdgeKind, IdentityGraph, NodeRef
from app.graph.semantics import (
    ALL_CAPABILITIES,
    EdgeType,
    can_assume,
    edge_types,
    effective_capabilities,
    manages_permission,
)
from app.models.capability import PRIVILEGED_CAPABILITIES, Capability
from tests.test_normalize import grant_ev, identity_ev, normalize, resource_ev

HOLDS, ASSUMES, MANAGES = EdgeType.HOLDS, EdgeType.ASSUMES, EdgeType.MANAGES_PERMISSION


def types_of(action: str, *, assumable: bool) -> frozenset[EdgeType]:
    """Classify one grant of `action` on a resource that is, or is not, a role."""
    extra = {"principal_id": "role_x"} if assumable else {}
    graph = IdentityGraph.from_estate(
        normalize(
            [
                identity_ev("alice"),
                identity_ev("role_x", payload={"identity_type": "role"}),
                resource_ev("r", payload=extra),
                grant_ev("g", "alice", "r", payload={"action": action}),
            ]
        )
    )
    [edge] = graph.out_edges(NodeRef.identity("alice"))
    return edge_types(edge, graph)


@pytest.mark.parametrize(
    "action, assumable, expected",
    [
        ("read", False, {HOLDS}),
        ("read", True, {HOLDS}),  # reading a role's resource is not becoming it
        ("impersonate", True, {HOLDS, ASSUMES}),
        # kwame and rahul today: impersonate on something with nobody behind it.
        ("impersonate", False, {HOLDS}),
        ("manage_identity", True, {HOLDS, ASSUMES}),  # reset its credentials
        ("manage_identity", False, {HOLDS}),
        ("manage_permission", False, {HOLDS, MANAGES}),
        ("manage_permission", True, {HOLDS, MANAGES, ASSUMES}),  # rewrite its trust
        ("admin", True, {HOLDS, MANAGES, ASSUMES}),
        ("destroy", True, {HOLDS}),
        ("some_vendor_verb", True, {HOLDS}),  # UNKNOWN confers nothing we can walk
    ],
)
def test_edge_types(action, assumable, expected):
    assert types_of(action, assumable=assumable) == frozenset(expected)


def test_structural_edges_have_no_meaning_of_their_own():
    graph = IdentityGraph.from_estate(
        normalize(
            [
                resource_ev("console", payload={"governs": ["db"], "principal_id": "role_x"}),
                resource_ev("db"),
                identity_ev("role_x", payload={"identity_type": "role"}),
            ]
        )
    )
    kinds = {e.kind for e in graph.edges}
    assert kinds == {EdgeKind.BECOMES, EdgeKind.GOVERNS}
    assert all(edge_types(e, graph) == frozenset() for e in graph.edges)


# --- The capability table --------------------------------------------------


def test_a_permission_manager_effectively_holds_everything():
    """It can grant itself admin; reporting only manage_permission understates it."""
    assert effective_capabilities(Capability.MANAGE_PERMISSION) == ALL_CAPABILITIES
    assert effective_capabilities(Capability.ADMIN) == ALL_CAPABILITIES
    assert Capability.UNKNOWN not in ALL_CAPABILITIES
    assert PRIVILEGED_CAPABILITIES <= ALL_CAPABILITIES


def test_other_capabilities_confer_only_themselves():
    for cap in Capability:
        if not manages_permission(cap):
            assert effective_capabilities(cap) == frozenset({cap})


def test_every_manager_can_also_assume():
    """Whoever can rewrite a role's trust policy can become the role."""
    assert all(can_assume(c) for c in Capability if manages_permission(c))


def test_ordinary_access_never_walks_anywhere():
    for cap in (Capability.AUTHENTICATE, Capability.READ, Capability.WRITE, Capability.UNKNOWN):
        assert not can_assume(cap) and not manages_permission(cap)
