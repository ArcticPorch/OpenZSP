"""
How much we actually know about an identity, as distinct from how risky it is.

This exists because `IdentityFeatures` answers "what did this identity do?" and
deliberately cannot answer "how much of what it did did we see?". Those are
different questions with different failure modes, and conflating them produces
the single worst outcome an ITDR engine can produce: reporting "all clear" at
the exact moment it has gone blind.

The `stale_connector_blind_spot` scenario is the canonical case. An identity
whose connector stopped delivering fourteen days ago presents at the feature
layer as simply quiet. Nothing in a feature vector distinguishes "did nothing"
from "we stopped watching" -- the distinguishing facts (completeness,
collection lag) are properties of the *evidence*, not of the identity.

Like `IdentityFeatures`, this DTO is interpretation-free: it holds proportions,
counts and elapsed days, never a trust score. Turning `min_completeness=0.4`
and `collection_staleness_days=14.0` into a confidence multiplier is a scoring
decision with a tunable decay curve, and it belongs in the scoring layer.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Protocol, Sequence, runtime_checkable

from app.common.validation import (
    validate_non_empty_str,
    validate_numeric,
    validate_tz_datetime,
)
from app.evidence.models import Evidence, RecordKind
from app.models.capability import Capability
from app.models.event import Event
from app.models.identity import Identity

# Elapsed-day fields are bounded only to reject NaN/inf. A tighter bound would be
# a judgement about plausible clock skew, which is not this layer's to make.
_DAYS_MIN = -1_000_000.0
_DAYS_MAX = 1_000_000.0
_SECONDS_PER_DAY = 86_400.0


@runtime_checkable
class EvidenceIndex(Protocol):
    """
    The provenance lookup this module needs, expressed structurally.

    `Estate` satisfies this without knowing it exists, which keeps `app.risk`
    from importing `app.normalize` merely to read a citation. Same reasoning as
    `EvidenceConnector`: the consumer declares the shape it needs, and the
    producer is never obliged to inherit from anything.

    Note that `@runtime_checkable` verifies method *names* only, never
    signatures -- an isinstance() pass here is a smoke test, not a guarantee.
    """

    def evidence_for(self, kind: RecordKind, entity_id: str) -> tuple[Evidence, ...]:
        ...

    def evidence_ids_for(self, kind: RecordKind, entity_id: str) -> tuple[str, ...]:
        ...


@dataclass(frozen=True)
class CoverageSummary:
    """
    Measurements of the evidence backing one identity. No trust scores.

    Every quality field aggregates by *minimum* rather than mean. Averaging is
    the wrong operator for a blind spot: an identity with nine perfect records
    and one from a connector reporting `completeness=0.4` has a mean near 0.94,
    which reads as healthy while describing an estate we are partly blind to.
    The weakest source determines what we might have missed, so the weakest
    source is what gets reported. Means are carried too, for the rules that
    genuinely want central tendency rather than worst case.
    """

    identity_id: str

    # --- Volume ---
    evidence_count: int
    source_count: int
    grant_evidence_count: int
    event_evidence_count: int

    # --- Quality, weakest-link ---
    min_completeness: float
    min_source_reliability: float
    min_identity_mapping_confidence: float
    min_integrity_authenticity: float

    # --- Quality, central tendency ---
    mean_completeness: float
    mean_source_reliability: float

    # --- Semantic coverage ---
    # Grants whose action this taxonomy could not classify. A second kind of
    # blindness, orthogonal to the collection kinds above: the feed is healthy,
    # current and complete, and we still do not know what the access confers.
    # Retained rather than dropped (dropping understates access), and surfaced
    # here so it suppresses confidence instead of passing as understood.
    unknown_capability_grant_count: int
    classified_grant_count: int

    # --- Bitemporal facts ---
    newest_collected_at: Optional[datetime]
    oldest_collected_at: Optional[datetime]
    newest_observed_at: Optional[datetime]
    # evaluation_time - newest_collected_at. Best case: "have we heard anything
    # at all lately". Optimistic by construction -- a single fresh record makes
    # this look healthy even when most sources have gone quiet.
    collection_staleness_days: Optional[float]
    # evaluation_time - oldest_collected_at. Weakest link, consistent with the
    # min_* quality fields: the record we are most behind on.
    max_collection_staleness_days: Optional[float]
    # Staleness of the evidence backing *activity* specifically. This is the
    # blind-spot signal a dormancy rule actually needs: an identity record can
    # be re-collected on every run while the event stream behind it dies, and
    # then "no recent activity" means "no recent collection". None when the
    # identity has no activity evidence at all, which is itself informative.
    activity_collection_staleness_days: Optional[float]
    # evaluation_time - newest_observed_at. The dormancy signal.
    observation_age_days: Optional[float]
    # May be negative: clock skew between a provider and the collector is normal.
    max_collection_lag_days: Optional[float]

    def __post_init__(self) -> None:
        validate_non_empty_str(self.identity_id, "identity_id")

        for name in (
            "evidence_count",
            "source_count",
            "grant_evidence_count",
            "event_evidence_count",
            "unknown_capability_grant_count",
            "classified_grant_count",
        ):
            val = getattr(self, name)
            if isinstance(val, bool) or not isinstance(val, int):
                raise TypeError(f"{name} must be an int, got {type(val).__name__}")
            if val < 0:
                raise ValueError(f"{name} must be non-negative, got {val}")

        for name in (
            "min_completeness",
            "min_source_reliability",
            "min_identity_mapping_confidence",
            "min_integrity_authenticity",
            "mean_completeness",
            "mean_source_reliability",
        ):
            validate_numeric(getattr(self, name), name, 0.0, 1.0)

        for name in ("newest_collected_at", "oldest_collected_at", "newest_observed_at"):
            val = getattr(self, name)
            if val is not None:
                validate_tz_datetime(val, name)

        for name in (
            "collection_staleness_days",
            "max_collection_staleness_days",
            "activity_collection_staleness_days",
            "observation_age_days",
            "max_collection_lag_days",
        ):
            val = getattr(self, name)
            if val is not None:
                validate_numeric(val, name, _DAYS_MIN, _DAYS_MAX)

    @property
    def has_evidence(self) -> bool:
        return self.evidence_count > 0

    @property
    def capability_coverage(self) -> float:
        """
        Share of this identity's grants whose capability we understand, 0..1.

        An identity with no grants returns 1.0: there is nothing we failed to
        classify, and returning 0.0 would punish an identity for holding no
        access, which is the state the product is trying to produce.
        """
        total = self.unknown_capability_grant_count + self.classified_grant_count
        if total == 0:
            return 1.0
        return self.classified_grant_count / total


class CoverageAnalyzer:
    """Builds a `CoverageSummary` from the provenance index. Stateless."""

    @staticmethod
    def summarize(
        identity: Identity,
        events: Sequence[Event],
        index: EvidenceIndex,
        evaluation_time: datetime,
    ) -> CoverageSummary:
        """
        Collects every record that contributed to this identity, its grants and
        its events, then reduces them to measurements.

        An identity with no evidence at all yields zeroed quality fields rather
        than 1.0. Absence of evidence is not evidence of absence: a rule reading
        `min_completeness == 0.0` should conclude "we know nothing here", which
        is the honest reading, rather than inheriting a default that asserts
        perfect knowledge of an identity we never actually observed.
        """
        validate_tz_datetime(evaluation_time, "evaluation_time")

        unknown_caps = sum(
            1 for p in identity.permissions if p.action is Capability.UNKNOWN
        )
        classified_caps = len(identity.permissions) - unknown_caps

        records: list[Evidence] = list(index.evidence_for(RecordKind.IDENTITY, identity.id))

        grant_records: list[Evidence] = []
        for perm in identity.permissions:
            grant_records.extend(index.evidence_for(RecordKind.PERMISSION_GRANT, perm.id))

        event_records: list[Evidence] = []
        for ev in events:
            if ev.identity_id == identity.id:
                event_records.extend(index.evidence_for(RecordKind.ACTIVITY_EVENT, ev.id))

        records.extend(grant_records)
        records.extend(event_records)

        # Re-collection is deduplicated by content address upstream, but the same
        # record can legitimately be reached twice here, so collapse on id before
        # aggregating -- otherwise a doubly-cited record skews every mean.
        unique: dict[str, Evidence] = {r.id: r for r in records}
        ordered = tuple(unique.values())

        if not ordered:
            return CoverageSummary(
                identity_id=identity.id,
                evidence_count=0,
                source_count=0,
                grant_evidence_count=0,
                event_evidence_count=0,
                min_completeness=0.0,
                min_source_reliability=0.0,
                min_identity_mapping_confidence=0.0,
                min_integrity_authenticity=0.0,
                mean_completeness=0.0,
                mean_source_reliability=0.0,
                unknown_capability_grant_count=unknown_caps,
                classified_grant_count=classified_caps,
                newest_collected_at=None,
                oldest_collected_at=None,
                newest_observed_at=None,
                collection_staleness_days=None,
                max_collection_staleness_days=None,
                activity_collection_staleness_days=None,
                observation_age_days=None,
                max_collection_lag_days=None,
            )

        n = len(ordered)
        newest_collected = max(r.collected_at for r in ordered)
        oldest_collected = min(r.collected_at for r in ordered)
        newest_observed = max(r.observed_at for r in ordered)
        max_lag = max(r.collection_lag for r in ordered)

        # Activity evidence is tracked separately: it is the stream that dies
        # quietly while the directory snapshot keeps refreshing.
        activity_staleness = None
        if event_records:
            newest_activity = max(r.collected_at for r in event_records)
            activity_staleness = (
                evaluation_time - newest_activity
            ).total_seconds() / _SECONDS_PER_DAY

        return CoverageSummary(
            identity_id=identity.id,
            evidence_count=n,
            source_count=len({str(r.source) for r in ordered}),
            grant_evidence_count=len({r.id for r in grant_records}),
            event_evidence_count=len({r.id for r in event_records}),
            min_completeness=min(r.quality.completeness for r in ordered),
            min_source_reliability=min(r.quality.source_reliability for r in ordered),
            min_identity_mapping_confidence=min(
                r.quality.identity_mapping_confidence for r in ordered
            ),
            min_integrity_authenticity=min(r.quality.integrity_authenticity for r in ordered),
            unknown_capability_grant_count=unknown_caps,
            classified_grant_count=classified_caps,
            mean_completeness=sum(r.quality.completeness for r in ordered) / n,
            mean_source_reliability=sum(r.quality.source_reliability for r in ordered) / n,
            newest_collected_at=newest_collected,
            oldest_collected_at=oldest_collected,
            newest_observed_at=newest_observed,
            collection_staleness_days=(evaluation_time - newest_collected).total_seconds()
            / _SECONDS_PER_DAY,
            max_collection_staleness_days=(evaluation_time - oldest_collected).total_seconds()
            / _SECONDS_PER_DAY,
            activity_collection_staleness_days=activity_staleness,
            observation_age_days=(evaluation_time - newest_observed).total_seconds()
            / _SECONDS_PER_DAY,
            max_collection_lag_days=max_lag.total_seconds() / _SECONDS_PER_DAY,
        )
