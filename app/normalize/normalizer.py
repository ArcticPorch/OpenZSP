"""
Evidence -> domain objects.

The seam where ingestion meets analysis. Three commitments shape this module:

1. It never raises on bad input. A single malformed record must not take down an
   ingestion run over a million rows, so unusable records become
   NormalizationIssue entries and everything else still normalizes. A pipeline
   that dies on row 900,000 has produced nothing; one that reports 12 bad rows
   has produced an answer plus a list of what to fix.

2. Provenance survives, but stays out of the domain model. Domain objects have
   no evidence_id field -- Identity is about identity, not about where the row
   came from. The Estate keeps a side index instead, so a rule can ask
   "which evidence produced this grant?" without the domain model growing
   ingestion concerns it would then carry forever.

3. Conflicts resolve deterministically. Same run, same input, same output --
   otherwise assessments are not reproducible and diffing two runs is noise.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

from app.evidence.models import Evidence, RecordKind
from app.models.event import Event, EventAction
from app.models.identity import Identity, IdentityType
from app.models.capability import Capability
from app.models.permission import GrantLifecycle, Permission
from app.models.resource import Exposure, Resource, ResourceType, Sensitivity


@dataclass(frozen=True)
class NormalizationIssue:
    """A record that could not be used, and why. Never an exception."""

    evidence_id: str
    record_kind: Optional[RecordKind]
    reason: str


class _RecordError(Exception):
    """Internal: one record is unusable. Caught and converted into an issue."""


@dataclass(frozen=True)
class Estate:
    """
    A normalized snapshot of the identity estate, plus its provenance index.

    "Estate" rather than "graph" deliberately: nothing here models access *paths*
    yet. Path/graph analysis (who can reach what by assuming which role) is a
    later layer and a different data structure.
    """

    identities: tuple[Identity, ...]
    resources: tuple[Resource, ...]
    events: tuple[Event, ...]
    issues: tuple[NormalizationIssue, ...]
    evidence_by_id: dict[str, Evidence] = field(default_factory=dict, repr=False)
    _provenance: dict[tuple[RecordKind, str], tuple[str, ...]] = field(
        default_factory=dict, repr=False
    )

    def evidence_for(self, kind: RecordKind, entity_id: str) -> tuple[Evidence, ...]:
        """Every record that contributed to an entity, newest observation last."""
        ids = self._provenance.get((kind, entity_id), ())
        return tuple(self.evidence_by_id[i] for i in ids)

    def evidence_ids_for(self, kind: RecordKind, entity_id: str) -> tuple[str, ...]:
        """Citation-ready ids, for RiskFactorAssessment.evidence_ids."""
        return self._provenance.get((kind, entity_id), ())

    def identity(self, identity_id: str) -> Optional[Identity]:
        return next((i for i in self.identities if i.id == identity_id), None)

    def resource(self, resource_id: str) -> Optional[Resource]:
        return next((r for r in self.resources if r.id == resource_id), None)


# --- Parsing helpers -------------------------------------------------------


def _require(payload: dict[str, Any], key: str) -> Any:
    if key not in payload:
        raise _RecordError(f"missing required payload key '{key}'")
    return payload[key]


def _require_ref(refs: dict[str, str], key: str) -> str:
    if key not in refs:
        raise _RecordError(f"missing required entity reference '{key}'")
    return refs[key]


def _parse_enum(enum_cls, raw: Any, field_name: str):
    """
    Unknown enum values are an issue, not a crash.

    A new IAM action or a new identity type appearing upstream is normal; the
    right response is to skip that record and report it, not to fail the run.
    """
    try:
        return enum_cls(raw)
    except (ValueError, TypeError):
        valid = ", ".join(sorted(m.value for m in enum_cls))
        raise _RecordError(f"unknown {field_name} {raw!r} (expected one of: {valid})")


def _parse_dt(raw: Any, field_name: str) -> datetime:
    if not isinstance(raw, str):
        raise _RecordError(f"{field_name} must be an ISO-8601 string, got {type(raw).__name__}")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        raise _RecordError(f"{field_name} is not valid ISO-8601: {raw!r}")
    if parsed.tzinfo is None:
        raise _RecordError(f"{field_name} must be timezone-aware: {raw!r}")
    return parsed


def _parse_bool(raw: Any, field_name: str) -> bool:
    if not isinstance(raw, bool):
        raise _RecordError(f"{field_name} must be a boolean, got {type(raw).__name__}")
    return raw


# --- Conflict resolution ---------------------------------------------------


def _winner(candidates: list[Evidence]) -> Evidence:
    """
    Last-write-wins on observed_at, breaking ties by source reliability and then
    by evidence id.

    LWW is chosen for its predictability, not because it is lossless -- it does
    discard what an older, more reliable source said about a field the newer one
    also set. A per-field merge weighted by source_reliability would preserve
    more, at the cost of producing objects that never existed in any single
    source, which is considerably harder to explain to an auditor. Explainability
    wins here; the losing records stay in the provenance index either way.

    The id tiebreak is arbitrary but total, which is the point: determinism.
    """
    return max(
        candidates,
        key=lambda e: (e.observed_at, e.quality.source_reliability, e.id),
    )


# --- Normalizer ------------------------------------------------------------


class Normalizer:
    """Turns a stream of Evidence into an Estate. Stateless between calls."""

    def normalize(self, evidence: Iterable[Evidence]) -> Estate:
        issues: list[NormalizationIssue] = []

        # Content-addressed ids make cross-source deduplication free: the same
        # fact collected twice collapses to one record with no comparison logic.
        by_id: dict[str, Evidence] = {}
        for ev in evidence:
            by_id.setdefault(ev.id, ev)

        buckets: dict[RecordKind, list[Evidence]] = {k: [] for k in RecordKind}
        for ev in by_id.values():
            buckets[ev.record_kind].append(ev)

        provenance: dict[tuple[RecordKind, str], list[str]] = {}

        def record_provenance(kind: RecordKind, entity_id: str, records: list[Evidence]) -> None:
            provenance[(kind, entity_id)] = [
                e.id for e in sorted(records, key=lambda e: (e.observed_at, e.id))
            ]

        # -- Resources --
        resources: dict[str, Resource] = {}
        for entity_id, group in self._group(buckets[RecordKind.RESOURCE], "resource_id", issues):
            try:
                resources[entity_id] = self._build_resource(entity_id, _winner(group))
            except _RecordError as exc:
                issues.append(
                    NormalizationIssue(_winner(group).id, RecordKind.RESOURCE, str(exc))
                )
                continue
            record_provenance(RecordKind.RESOURCE, entity_id, group)

        # -- Permissions (grouped per identity) --
        grants_by_identity: dict[str, list[Permission]] = {}
        for entity_id, group in self._group(
            buckets[RecordKind.PERMISSION_GRANT], "grant_id", issues
        ):
            win = _winner(group)
            try:
                perm = self._build_permission(entity_id, win)
            except _RecordError as exc:
                issues.append(
                    NormalizationIssue(win.id, RecordKind.PERMISSION_GRANT, str(exc))
                )
                continue

            # A grant pointing at an unknown resource is kept, not dropped. The
            # feature layer already treats unknown sensitivity as "not critical",
            # and silently discarding a grant would understate someone's access
            # -- the one direction a privilege engine must never err in.
            if perm.resource_id not in resources:
                issues.append(
                    NormalizationIssue(
                        win.id,
                        RecordKind.PERMISSION_GRANT,
                        f"references unknown resource '{perm.resource_id}'; "
                        "grant retained with unknown sensitivity",
                    )
                )
            grants_by_identity.setdefault(perm.identity_id, []).append(perm)
            record_provenance(RecordKind.PERMISSION_GRANT, entity_id, group)

        # -- Identities --
        identities: dict[str, Identity] = {}
        for entity_id, group in self._group(buckets[RecordKind.IDENTITY], "identity_id", issues):
            win = _winner(group)
            try:
                identities[entity_id] = self._build_identity(
                    entity_id,
                    win,
                    sorted(grants_by_identity.pop(entity_id, []), key=lambda p: p.id),
                )
            except _RecordError as exc:
                issues.append(NormalizationIssue(win.id, RecordKind.IDENTITY, str(exc)))
                continue
            record_provenance(RecordKind.IDENTITY, entity_id, group)

        # Grants left over reference an identity we never saw. Reported rather
        # than dropped silently: an orphaned admin grant is itself a finding.
        for orphan_identity, perms in grants_by_identity.items():
            for perm in perms:
                issues.append(
                    NormalizationIssue(
                        perm.id,
                        RecordKind.PERMISSION_GRANT,
                        f"grant references unknown identity '{orphan_identity}'",
                    )
                )

        # -- Events --
        events: dict[str, Event] = {}
        for entity_id, group in self._group(
            buckets[RecordKind.ACTIVITY_EVENT], "event_id", issues
        ):
            win = _winner(group)
            try:
                events[entity_id] = self._build_event(entity_id, win)
            except _RecordError as exc:
                issues.append(
                    NormalizationIssue(win.id, RecordKind.ACTIVITY_EVENT, str(exc))
                )
                continue
            record_provenance(RecordKind.ACTIVITY_EVENT, entity_id, group)

        for ev in buckets[RecordKind.POLICY_DOCUMENT]:
            issues.append(
                NormalizationIssue(
                    ev.id,
                    RecordKind.POLICY_DOCUMENT,
                    "policy documents require the resolution layer, which is not implemented",
                )
            )

        return Estate(
            identities=tuple(identities[k] for k in sorted(identities)),
            resources=tuple(resources[k] for k in sorted(resources)),
            events=tuple(events[k] for k in sorted(events)),
            issues=tuple(issues),
            evidence_by_id=by_id,
            _provenance={k: tuple(v) for k, v in provenance.items()},
        )

    # -- grouping ---------------------------------------------------------

    @staticmethod
    def _group(
        records: list[Evidence], ref_key: str, issues: list[NormalizationIssue]
    ) -> list[tuple[str, list[Evidence]]]:
        grouped: dict[str, list[Evidence]] = {}
        for ev in records:
            entity_id = ev.references_dict().get(ref_key)
            if not entity_id:
                issues.append(
                    NormalizationIssue(
                        ev.id, ev.record_kind, f"missing entity reference '{ref_key}'"
                    )
                )
                continue
            grouped.setdefault(entity_id, []).append(ev)
        return sorted(grouped.items())

    # -- builders ---------------------------------------------------------

    @staticmethod
    def _build_identity(
        identity_id: str, ev: Evidence, permissions: list[Permission]
    ) -> Identity:
        p = ev.payload_dict()
        return Identity(
            id=identity_id,
            name=_require(p, "name"),
            identity_type=_parse_enum(IdentityType, _require(p, "identity_type"), "identity_type"),
            department=_require(p, "department"),
            # Optional: a source that knows nothing about tenancy yields an
            # internal principal rather than a normalization issue.
            is_external=bool(p.get("is_external", False)),
            permissions=permissions,
        )

    @staticmethod
    def _build_resource(resource_id: str, ev: Evidence) -> Resource:
        p = ev.payload_dict()
        return Resource(
            id=resource_id,
            name=_require(p, "name"),
            resource_type=_parse_enum(ResourceType, _require(p, "resource_type"), "resource_type"),
            sensitivity=_parse_enum(Sensitivity, _require(p, "sensitivity"), "sensitivity"),
            # Optional: absent exposure evidence means INTERNAL, not unknown.
            # See the note on Exposure for why the safe default is the quiet one.
            exposure=_parse_enum(Exposure, p.get("exposure", "internal"), "exposure"),
        )

    @staticmethod
    def _build_permission(grant_id: str, ev: Evidence) -> Permission:
        p = ev.payload_dict()
        refs = ev.references_dict()
        try:
            return Permission(
                id=grant_id,
                identity_id=_require_ref(refs, "identity_id"),
                resource_id=_require_ref(refs, "resource_id"),
                # Never _parse_enum here. An unrecognised action must NOT
                # drop the grant: this file already holds that understating
                # access is the one direction a privilege engine must not err
                # in, and a dropped grant understates it silently. Unmapped
                # actions become Capability.UNKNOWN, are retained, and suppress
                # confidence downstream instead.
                action=Capability.from_token(_require(p, "action")),
                lifecycle=_parse_enum(
                    GrantLifecycle, p.get("lifecycle", "standing"), "lifecycle"
                ),
                granted_at=_parse_dt(p["granted_at"], "granted_at") if "granted_at" in p else None,
                expires_at=_parse_dt(p["expires_at"], "expires_at") if "expires_at" in p else None,
            )
        except (ValueError, TypeError) as exc:
            # Permission enforces its own invariants (e.g. time_bound requires an
            # expiry). Surface that as an issue rather than letting it escape.
            raise _RecordError(str(exc))

    @staticmethod
    def _build_event(event_id: str, ev: Evidence) -> Event:
        p = ev.payload_dict()
        refs = ev.references_dict()
        return Event(
            id=event_id,
            identity_id=_require_ref(refs, "identity_id"),
            resource_id=_require_ref(refs, "resource_id"),
            action=_parse_enum(EventAction, _require(p, "action"), "action"),
            # observed_at, not collected_at: when the thing happened, not when we
            # heard about it. Using collection time here would silently shift
            # every event in a backfill into the present and light up every
            # recency window at once.
            timestamp=ev.observed_at,
            success=_parse_bool(_require(p, "success"), "success"),
        )
