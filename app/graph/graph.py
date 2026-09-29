"""
The identity-resource graph: the estate as something you can walk.

`Estate` answers "what does this identity hold?". It cannot answer "what can
this identity *reach*?", because the answer runs through other principals: hold
impersonate on a role's resource, become the role, inherit what the role holds.
That question needs a graph, and this module builds one from the domain
objects. It does not walk it -- traversal is its own layer.

Three commitments shape it:

1. **Timeless and interpretation-free**, like `IdentityFeatures`. Every grant
   becomes an edge carrying its `Permission` -- lifecycle, expiry and all --
   including JIT-eligible grants and expired ones still present. Whether an
   edge counts *at time t* is decided during traversal, never at build time.
   Dropping JIT edges here would make "reachable only via JIT" unaskable, and
   dropping expired ones would hide the failed revocation that usually still
   works.

2. **Nodes are keyed by (kind, id), never a bare id.** Identities and resources
   are separate namespaces. A role's two sides are joined only by
   `Resource.principal_id`; if nodes were keyed by id, an identity and a
   resource that happen to share a name would merge and invent an access path.

3. **Dangling references become bare nodes, not gaps.** A grant on a resource
   we never saw still leads *somewhere*, and a role link to an unknown principal
   still exists. Dropping either would understate reach -- the one direction a
   privilege engine must not err in. Such nodes carry no attributes, which is
   how later layers tell "unknown" from "harmless".

The graph depends only on `app/models`. It is built from identities and
resources, so this layer never imports the normalizer; `from_estate` accepts
anything shaped like an `Estate`.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional, Protocol, Sequence

from app.common.validation import validate_non_empty_str
from app.models.identity import Identity
from app.models.permission import Permission
from app.models.resource import Resource


class NodeKind(Enum):
    IDENTITY = "identity"
    RESOURCE = "resource"


@dataclass(frozen=True)
class NodeRef:
    """A node's address. The kind is part of it, so namespaces cannot collide."""

    kind: NodeKind
    id: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, NodeKind):
            raise TypeError(f"kind must be a NodeKind, got {type(self.kind).__name__}")
        validate_non_empty_str(self.id, "id")

    @classmethod
    def identity(cls, identity_id: str) -> "NodeRef":
        return cls(NodeKind.IDENTITY, identity_id)

    @classmethod
    def resource(cls, resource_id: str) -> "NodeRef":
        return cls(NodeKind.RESOURCE, resource_id)

    @property
    def sort_key(self) -> tuple[str, str]:
        return (self.kind.value, self.id)


class EdgeKind(Enum):
    """
    Structural edges only. What a grant edge *means* for traversal -- plain
    access, a step into another principal, the power to grant -- is read from
    its capability, not baked into the kind.
    """

    GRANT = "grant"      # identity -> resource: holds this permission on it
    BECOMES = "becomes"  # resource -> identity: impersonating it makes you them


@dataclass(frozen=True)
class Edge:
    kind: EdgeKind
    source: NodeRef
    target: NodeRef
    # Set on GRANT edges, never on BECOMES. The edge carries the permission
    # itself rather than a copy of its fields, so lifecycle and expiry are
    # judged by `Permission`'s own methods and cannot drift.
    permission: Optional[Permission] = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EdgeKind):
            raise TypeError(f"kind must be an EdgeKind, got {type(self.kind).__name__}")
        if self.kind is EdgeKind.GRANT:
            if not isinstance(self.permission, Permission):
                raise TypeError("a grant edge must carry its Permission")
            if self.source != NodeRef.identity(self.permission.identity_id):
                raise ValueError("a grant edge must start at the grant's identity")
            if self.target != NodeRef.resource(self.permission.resource_id):
                raise ValueError("a grant edge must end at the grant's resource")
        else:
            if self.permission is not None:
                raise ValueError("a becomes edge carries no permission")
            if self.source.kind is not NodeKind.RESOURCE:
                raise ValueError("a becomes edge must start at a resource")
            if self.target.kind is not NodeKind.IDENTITY:
                raise ValueError("a becomes edge must end at an identity")

    @property
    def edge_id(self) -> str:
        """
        Stable and derived, never generated, so paths are diffable across runs.
        A grant edge is its grant; a resource becomes at most one principal.
        """
        if self.permission is not None:
            return self.permission.id
        return f"becomes:{self.source.id}"

    @property
    def sort_key(self) -> tuple:
        return (*self.source.sort_key, self.kind.value, *self.target.sort_key, self.edge_id)


class EstateLike(Protocol):
    """What `from_estate` needs. `Estate` satisfies it structurally."""

    identities: Sequence[Identity]
    resources: Sequence[Resource]


@dataclass(frozen=True)
class IdentityGraph:
    """
    Nodes and edges in sorted order, plus lookup indices.

    Two builds over the same estate are equal whatever order the input came
    in; equality compares nodes and edges only.
    """

    nodes: tuple[NodeRef, ...]
    edges: tuple[Edge, ...]
    _identities: dict[str, Identity] = field(default_factory=dict, repr=False, compare=False)
    _resources: dict[str, Resource] = field(default_factory=dict, repr=False, compare=False)
    _out: dict[NodeRef, tuple[Edge, ...]] = field(
        default_factory=dict, repr=False, compare=False
    )

    @classmethod
    def build(
        cls, identities: Iterable[Identity], resources: Iterable[Resource]
    ) -> "IdentityGraph":
        by_identity = _unique(identities, "identity")
        by_resource = _unique(resources, "resource")

        nodes: set[NodeRef] = set()
        edges: list[Edge] = []

        for resource in by_resource.values():
            node = NodeRef.resource(resource.id)
            nodes.add(node)
            if resource.principal_id is not None:
                principal = NodeRef.identity(resource.principal_id)
                nodes.add(principal)
                edges.append(Edge(EdgeKind.BECOMES, node, principal))

        for identity in by_identity.values():
            node = NodeRef.identity(identity.id)
            nodes.add(node)
            for perm in identity.permissions:
                target = NodeRef.resource(perm.resource_id)
                nodes.add(target)
                edges.append(Edge(EdgeKind.GRANT, node, target, perm))

        edges.sort(key=lambda e: e.sort_key)
        out: dict[NodeRef, list[Edge]] = {}
        for edge in edges:
            out.setdefault(edge.source, []).append(edge)

        return cls(
            nodes=tuple(sorted(nodes, key=lambda n: n.sort_key)),
            edges=tuple(edges),
            _identities=by_identity,
            _resources=by_resource,
            _out={node: tuple(es) for node, es in out.items()},
        )

    @classmethod
    def from_estate(cls, estate: EstateLike) -> "IdentityGraph":
        return cls.build(estate.identities, estate.resources)

    # --- Lookups (O(1)) ----------------------------------------------------

    def out_edges(self, node: NodeRef) -> tuple[Edge, ...]:
        """Edges leaving a node, in a fixed order so traversal is deterministic."""
        return self._out.get(node, ())

    def identity(self, identity_id: str) -> Optional[Identity]:
        """None for a bare node: referenced, but never observed."""
        return self._identities.get(identity_id)

    def resource(self, resource_id: str) -> Optional[Resource]:
        """None for a bare node: its sensitivity and exposure are unknown."""
        return self._resources.get(resource_id)

    def is_bare(self, node: NodeRef) -> bool:
        if node.kind is NodeKind.IDENTITY:
            return node.id not in self._identities
        return node.id not in self._resources


def _unique(items: Iterable, what: str) -> dict:
    by_id: dict = {}
    for item in items:
        if item.id in by_id:
            raise ValueError(f"duplicate {what} id {item.id!r}")
        by_id[item.id] = item
    return by_id
