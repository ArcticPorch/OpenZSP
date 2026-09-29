"""
What a grant edge means for reach.

The graph is structural: a grant edge says "holds capability X on resource R"
and nothing more. This module is where that becomes traversal meaning. It is
the single place those meanings are written down, so the walk, the path
explanation and every graph rule read one definition.

Three edge types, and one grant can be several at once -- admin on a role's
resource is all three:

* **holds**: the capability on the resource. Every grant is this.
* **assumes**: the resource is also a principal (`Resource.principal_id`) and
  the capability is enough to become it. Impersonating is the obvious case;
  resetting its credentials (manage identity) or rewriting its trust policy
  (manage permission, admin) gets you the same principal by another door.
* **manages-permission**: the holder can grant itself anything on the resource,
  so it effectively holds every capability there, and permission management on
  a control plane carries over to every resource it `governs`.

Each meaning is stated per *capability*, not per edge, so the walk can apply
it to capabilities that were derived rather than granted: manage-permission on
a console that governs a role's resource is enough to become that role, with no
grant on the role anywhere.
"""

from enum import Enum

from app.graph.graph import Edge, EdgeKind, IdentityGraph
from app.models.capability import Capability


class EdgeType(Enum):
    HOLDS = "holds"
    ASSUMES = "assumes"
    MANAGES_PERMISSION = "manages_permission"


# Enough to become the principal behind a resource.
ASSUMING_CAPABILITIES: frozenset[Capability] = frozenset(
    {
        Capability.IMPERSONATE,
        Capability.MANAGE_IDENTITY,
        Capability.MANAGE_PERMISSION,
        Capability.ADMIN,
    }
)

# Enough to grant yourself anything on the resource, and on what it governs.
# MANAGE_IDENTITY is not here: resetting who someone is gets you *them*, not
# the right to rewrite what the resource allows.
MANAGING_CAPABILITIES: frozenset[Capability] = frozenset(
    {Capability.MANAGE_PERMISSION, Capability.ADMIN}
)

# Everything a manager can grant itself. UNKNOWN is not a capability anyone
# can grant; it is a gap in our understanding.
ALL_CAPABILITIES: frozenset[Capability] = frozenset(Capability) - {Capability.UNKNOWN}


def can_assume(capability: Capability) -> bool:
    return capability in ASSUMING_CAPABILITIES


def manages_permission(capability: Capability) -> bool:
    return capability in MANAGING_CAPABILITIES


def effective_capabilities(capability: Capability) -> frozenset[Capability]:
    """
    What holding `capability` on a resource amounts to on that resource.

    A permission manager can grant itself admin, so pretending it holds only
    "manage_permission" understates it. Anything else confers exactly itself.
    """
    if manages_permission(capability):
        return ALL_CAPABILITIES
    return frozenset({capability})


def edge_types(edge: Edge, graph: IdentityGraph) -> frozenset[EdgeType]:
    """The meanings of one grant edge. Structural edges have none of their own."""
    if edge.kind is not EdgeKind.GRANT:
        return frozenset()
    capability = edge.permission.action
    types = {EdgeType.HOLDS}
    if manages_permission(capability):
        types.add(EdgeType.MANAGES_PERMISSION)
    if can_assume(capability) and graph.principal_of(edge.target) is not None:
        types.add(EdgeType.ASSUMES)
    return frozenset(types)
