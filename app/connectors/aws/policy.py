"""
IAM effective-permission evaluation: which capabilities a principal really has
on a resource, after every policy type has had its say.

Evaluated per (principal, resource) at **action level**, never capability
level. Allow `s3:*` plus Deny `s3:DeleteObject` must leave DESTROY standing --
`s3:DeleteBucket` is still allowed -- and subtracting capabilities would wipe
it, understating access, the one direction this engine must not err in. So
the universe is the resource's service's actions from AWS's own table, and:

    allowed = identity-policy allows (user, its groups, or role)
            | resource-policy allows naming this principal
    allowed -= unconditional explicit denies (identity, boundary, SCP, resource)
    identity-policy allows must also pass the permission boundary, if any
    everything must pass every SCP level (AWS: within a level any SCP may
    allow; across levels all must)

then the surviving actions map to capabilities (all of them surviving is ADMIN).

Approximations, chosen to never understate:

* **Conditions are never assumed false.** A conditional Allow still grants; the
  result records that the capability rests only on conditional allows, and the
  condition keys, so the connector can lower confidence. A conditional Deny is
  *not* trusted to block -- "maybe denied" cannot remove access.
* **Children count as the resource.** A statement on `arn:aws:s3:::bucket/*`
  is access to the bucket resource: the objects are what the bucket holds.
* **A resource policy naming the account root delegates** to identity policies
  and grants nothing by itself; naming the principal's ARN grants directly;
  `"*"` grants everyone (and makes the resource public).
* **The boundary limits identity-policy allows only**, not a resource policy
  that names the principal (AWS's same-account rule for users; roles are
  treated the same here, which can only overstate).
* **A role is assumable only if its trust policy agrees**: it names the
  principal (that alone suffices), or names the account root and an identity
  policy allows `sts:AssumeRole` on the role. Without this, `sts:AssumeRole`
  on `*` would read as "can become every role", service-only roles included.
* Session policies, VPC endpoint policies and cross-account trust are out of
  scope -- the export does not carry them.
"""

import fnmatch
from dataclasses import dataclass, field
from typing import Iterable, Optional

from app.connectors.aws.actions import (
    action_levels,
    action_resource_types,
    arn_patterns,
    capability_of_action,
)
from app.models.capability import Capability

_ASSUME_ACTIONS = ("sts:assumerole", "sts:assumerolewithsaml", "sts:assumerolewithwebidentity")


@dataclass(frozen=True)
class Statement:
    policy_id: str
    effect: str  # "Allow" | "Deny"
    actions: Optional[tuple[str, ...]]  # lower-case patterns; None when NotAction is used
    not_actions: tuple[str, ...]
    resources: Optional[tuple[str, ...]]  # None when NotResource is used
    not_resources: tuple[str, ...]
    principals: Optional[tuple[str, ...]]  # resource policies only; "*" for anyone
    condition_keys: tuple[str, ...]
    # NotPrincipal: everyone except these. Rare and discouraged by AWS, but a
    # Deny with NotPrincipal is how some accounts lock a bucket to one role.
    not_principals: tuple[str, ...] = ()

    @property
    def conditional(self) -> bool:
        return bool(self.condition_keys)


def _as_tuple(value) -> tuple:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def _principals(raw) -> Optional[tuple[str, ...]]:
    if raw is None:
        return None
    if raw == "*":
        return ("*",)
    out: list[str] = []
    for key, value in raw.items():
        for item in _as_tuple(value):
            if item == "*":
                out.append("*")
            elif key == "AWS" and item.isdigit():
                out.append(f"arn:aws:iam::{item}:root")  # a bare account id means its root
            else:
                out.append(item if key == "AWS" else f"{key}:{item}")
    return tuple(out)


def parse_policy(document: dict, policy_id: str) -> tuple[Statement, ...]:
    """A policy document (already JSON-decoded) -> its statements."""
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    out = []
    for raw in statements:
        actions = raw.get("Action")
        resources = raw.get("Resource")
        conditions = raw.get("Condition") or {}
        keys = sorted({k for operator in conditions.values() for k in operator})
        out.append(Statement(
            policy_id=policy_id,
            effect=raw.get("Effect", "Allow"),
            actions=tuple(a.lower() for a in _as_tuple(actions)) if actions is not None else None,
            not_actions=tuple(a.lower() for a in _as_tuple(raw.get("NotAction"))),
            resources=_as_tuple(resources) if resources is not None else None,
            not_resources=_as_tuple(raw.get("NotResource")),
            principals=_principals(raw.get("Principal")),
            condition_keys=tuple(keys),
            not_principals=_principals(raw.get("NotPrincipal")) or (),
        ))
    return tuple(out)


def service_of(arn: str) -> str:
    return arn.split(":")[2] if arn.count(":") >= 5 else ""


def _arn_matches(pattern: str, arn: str) -> bool:
    """
    IAM resource matching with `*` and `?`. A statement on the resource's
    children -- `arn:aws:s3:::bucket/*`, `.../bucket/reports/*` -- is access to
    the resource, since the children are what it holds.
    """
    if fnmatch.fnmatchcase(arn, pattern):
        return True
    return fnmatch.fnmatchcase(arn + "/child", pattern) or pattern.startswith(arn + "/")


def _resource_applies(statement: Statement, arn: str) -> bool:
    if statement.resources is not None:
        return any(_arn_matches(p, arn) for p in statement.resources)
    return not any(_arn_matches(p, arn) for p in statement.not_resources)


def _actions_of(statement: Statement, universe: Iterable[str]) -> set[str]:
    if statement.actions is not None:
        return {a for a in universe if any(fnmatch.fnmatchcase(a, p) for p in statement.actions)}
    return {a for a in universe if not any(fnmatch.fnmatchcase(a, p) for p in statement.not_actions)}


def _principal_named(statement: Statement, principal_arn: str, *, anyone: bool = True) -> bool:
    """
    Whether a resource-policy statement names this principal. `anyone=False`
    ignores `"*"`: a public Allow is exposure of the resource (see `is_public`),
    not a grant held by each identity -- otherwise every principal in the
    account would "hold" read on every public bucket.
    """
    if statement.principals is None and statement.not_principals:
        # Everyone except the listed principals: as broad as "*" for everyone else.
        excluded = any(fnmatch.fnmatchcase(principal_arn, p) for p in statement.not_principals)
        return anyone and not excluded
    return bool(statement.principals) and any(
        (p == "*" and anyone) or (p != "*" and fnmatch.fnmatchcase(principal_arn, p))
        for p in statement.principals
    )


def universe_for(resource_arn: str) -> list[str]:
    """
    Every action that can target this resource, per AWS's own resource types:
    an action counts if one of its resource types' ARN formats matches the ARN
    or the resource's children (an object action counts toward its bucket).
    Account-level actions (no resource type) target no particular resource.

    Without this, `cloudtrail:DeleteEventDataStore` would count against a
    *trail's* ARN -- a different resource type -- and overstate access. If an
    ARN matches no known format (a new type, an unusual ARN), the whole service
    is used instead: overstating is the safe failure. The account's IAM
    control plane (`.../account-iam`) is all of IAM. Role assumption is added
    on a role.
    """
    service = service_of(resource_arn)
    if service == "iam" and resource_arn.endswith(":account-iam"):
        return [f"iam:{name}" for name in action_levels().get("iam", {})]
    patterns = arn_patterns(service)
    matching = {
        rtype for rtype, globs in patterns.items()
        if any(fnmatch.fnmatchcase(resource_arn, g) or fnmatch.fnmatchcase(resource_arn + "/child", g)
               for g in globs)
    }
    by_action = action_resource_types(service)
    if matching:
        actions = [f"{service}:{a}" for a, types in by_action.items() if matching & set(types)]
    else:
        actions = [f"{service}:{a}" for a in by_action]
    if service == "iam" and ":role/" in resource_arn:
        actions += list(_ASSUME_ACTIONS)
    return actions


@dataclass
class _Grant:
    unconditional: bool = False
    condition_keys: set = field(default_factory=set)
    sources: set = field(default_factory=set)


@dataclass(frozen=True)
class EffectiveCapability:
    capability: Capability
    conditional: bool  # rests only on Allow statements that carry conditions
    condition_keys: tuple[str, ...]
    sources: tuple[str, ...]  # policy ids whose Allow statements confer it


def effective_capabilities(
    principal_arn: str,
    resource_arn: str,
    identity_statements: Iterable[Statement],
    resource_statements: Iterable[Statement] = (),
    boundary: Optional[Iterable[Statement]] = None,
    scp_levels: Iterable[Iterable[Statement]] = (),
    account_root: str = "",
) -> tuple[EffectiveCapability, ...]:
    universe = universe_for(resource_arn)
    if not universe:
        return ()
    identity_statements = tuple(identity_statements)
    resource_statements = tuple(resource_statements)
    boundary = tuple(boundary) if boundary is not None else None
    scp_levels = [tuple(level) for level in scp_levels]

    def applicable(statements, effect, *, need_principal=False):
        for s in statements:
            if s.effect != effect or not _resource_applies(s, resource_arn):
                continue
            if need_principal:
                if not _principal_named(s, principal_arn, anyone=False):
                    continue
            yield s

    def allowed_by(statements) -> set[str]:
        out: set[str] = set()
        for s in applicable(statements, "Allow"):
            out |= _actions_of(s, universe)
        return out

    grants: dict[str, _Grant] = {}

    def add(statement: Statement, actions: set[str]) -> None:
        for action in actions:
            g = grants.setdefault(action, _Grant())
            g.sources.add(statement.policy_id)
            if statement.conditional:
                g.condition_keys.update(statement.condition_keys)
            else:
                g.unconditional = True

    boundary_allows = allowed_by(boundary) if boundary is not None else None
    for s in applicable(identity_statements, "Allow"):
        actions = _actions_of(s, universe)
        if boundary_allows is not None:
            actions &= boundary_allows
        add(s, actions)
    for s in applicable(resource_statements, "Allow", need_principal=True):
        add(s, _actions_of(s, universe))

    denied: set[str] = set()
    deny_sources = list(identity_statements) + list(resource_statements) + list(boundary or ())
    for level in scp_levels:
        deny_sources += list(level)
    for s in deny_sources:
        if s.effect != "Deny" or s.conditional or not _resource_applies(s, resource_arn):
            continue
        if (s.principals is not None or s.not_principals) and not _principal_named(s, principal_arn):
            continue
        denied |= _actions_of(s, universe)

    surviving = set(grants) - denied
    for level in scp_levels:
        surviving &= allowed_by(level)

    # Role assumption needs the role's consent: its trust policy (passed as the
    # resource statements) must name this principal or the account root.
    if service_of(resource_arn) == "iam" and ":role/" in resource_arn:
        for action in _ASSUME_ACTIONS:
            trusted = any(
                s.effect == "Allow"
                and action in _actions_of(s, [action])
                and (_principal_named(s, principal_arn)
                     or (account_root and _principal_named(s, account_root)))
                for s in resource_statements
            )
            if not trusted:
                surviving.discard(action)

    if not surviving:
        return ()
    by_capability: dict[Capability, _Grant] = {}
    # Every action surviving is ADMIN, and only ADMIN: emitting its components
    # (manage_permission, destroy, ...) as separate grants would make every
    # admin also a permission manager, the double count the rules avoid.
    if surviving >= set(universe):
        merged = _Grant()
        for action in surviving:
            g = grants[action]
            merged.unconditional |= g.unconditional
            merged.condition_keys |= g.condition_keys
            merged.sources |= g.sources
        surviving = set()
        by_capability[Capability.ADMIN] = merged
    for action in surviving:
        g = grants[action]
        cap = capability_of_action(action)
        merged = by_capability.setdefault(cap, _Grant())
        merged.unconditional |= g.unconditional
        merged.condition_keys |= g.condition_keys
        merged.sources |= g.sources
    return tuple(
        EffectiveCapability(
            capability=cap,
            conditional=not g.unconditional,
            condition_keys=tuple(sorted(g.condition_keys)) if not g.unconditional else (),
            sources=tuple(sorted(g.sources)),
        )
        for cap, g in sorted(by_capability.items(), key=lambda kv: kv[0].value)
    )


def fenced_by_scp(resource_arn: str, scp_levels: Iterable[Iterable[Statement]]) -> bool:
    """
    Whether an SCP unconditionally denies any action that can target this
    resource. An SCP is a ceiling IAM cannot grant past, so a fenced resource
    must not be treated as governed by the account's IAM control plane --
    otherwise an IAM admin would "reach" exactly what the SCP forbids.
    """
    universe = universe_for(resource_arn)
    return any(
        s.effect == "Deny" and not s.conditional and _resource_applies(s, resource_arn)
        and _actions_of(s, universe)
        for level in scp_levels for s in level
    )


def is_public(resource_statements: Iterable[Statement]) -> bool:
    """An unconditional Allow to principal "*": reachable by anyone."""
    return any(
        s.effect == "Allow" and not s.conditional
        and (s.principals == ("*",) or (s.principals is None and s.not_principals))
        for s in resource_statements
    )
