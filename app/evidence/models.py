"""
The evidence envelope: a single trust-scored observation from some source.

Everything the engine eventually asserts must be traceable back to one or more
Evidence records, so this is the bottom of the dependency graph -- the risk
package imports from here, never the reverse.

Evidence is *both* the raw-record envelope and the citation target. A connector
emits Evidence; a normalizer turns Evidence into domain objects; a rule cites
the Evidence ids that made it fire. Keeping it as one concept means there is no
second representation to drift out of sync.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import json
from typing import Any

from app.common.validation import (
    validate_keyed_tuple,
    validate_non_empty_str,
    validate_numeric,
    validate_str_pair_tuple,
    validate_tz_datetime,
)


class SourceType(Enum):
    """Where an observation came from. Drives default reliability and decay tuning."""

    SYNTHETIC = "synthetic"
    AWS_IAM_SNAPSHOT = "aws_iam_snapshot"
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    AWS_ACCESS_ANALYZER = "aws_access_analyzer"
    OKTA_DIRECTORY = "okta_directory"
    MANUAL_ATTESTATION = "manual_attestation"


class RecordKind(Enum):
    """
    What an observation is *about*. The discriminator the normalizer dispatches on.

    Lives on the envelope rather than inside the payload so a stream can be
    filtered without parsing, and so a connector cannot emit an unroutable record
    by forgetting a magic key.

    POLICY_DOCUMENT is the raw, unresolved artifact -- an IAM policy JSON as
    fetched. PERMISSION_GRANT is the *effective* grant derived from it. Keeping
    both means a resolved grant can cite the policy document it came from, which
    is the difference between "you have admin" and "you have admin, via this
    policy, on this line".
    """

    IDENTITY = "identity"
    RESOURCE = "resource"
    POLICY_DOCUMENT = "policy_document"
    PERMISSION_GRANT = "permission_grant"
    ACTIVITY_EVENT = "activity_event"


@dataclass(frozen=True)
class SourceRef:
    """
    Identifies the concrete origin of an observation.

    `source_id` is the scope the connector read from -- an AWS account/region, an
    Okta tenant, a file path. Two connectors of the same SourceType pointed at
    different accounts must not collide, which is why the id is carried
    separately rather than folded into the type.
    """

    source_type: SourceType
    source_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.source_type, SourceType):
            raise TypeError(
                f"source_type must be a SourceType, got {type(self.source_type).__name__}"
            )
        validate_non_empty_str(self.source_id, "source_id")

    def __str__(self) -> str:
        return f"{self.source_type.value}:{self.source_id}"


@dataclass(frozen=True)
class EvidenceQuality:
    """
    How much this observation should be trusted, on grounds that do not change
    with time.

    Deliberately does NOT carry a freshness score. Freshness is a function of
    (evidence, evaluation_time) and cannot be frozen at collection: a record that
    stored freshness=0.95 ninety days ago would still claim 0.95 today. The raw
    timestamps live on Evidence and the scoring layer derives freshness from them
    against the evaluation time, which keeps this DTO a set of facts rather than
    a set of expiring opinions.
    """

    source_reliability: float
    integrity_authenticity: float
    identity_mapping_confidence: float
    completeness: float

    def __post_init__(self) -> None:
        validate_numeric(self.source_reliability, "source_reliability", 0.0, 1.0)
        validate_numeric(self.integrity_authenticity, "integrity_authenticity", 0.0, 1.0)
        validate_numeric(
            self.identity_mapping_confidence, "identity_mapping_confidence", 0.0, 1.0
        )
        validate_numeric(self.completeness, "completeness", 0.0, 1.0)


@dataclass(frozen=True)
class Evidence:
    """
    One observation, with provenance.

    Bitemporal by design:
      observed_at  -- when the fact was true in the world
      collected_at -- when this pipeline learned about it

    The gap between them is itself a signal. A silently failing connector yields
    records whose observed_at looks recent while collected_at falls further and
    further behind, which is how a deployment goes blind without any rule firing.
    An engine tracking a single timestamp cannot distinguish "nothing risky
    happened" from "we stopped receiving data".
    """

    id: str
    source: SourceRef
    record_kind: RecordKind
    observed_at: datetime
    collected_at: datetime
    quality: EvidenceQuality
    entity_references: tuple[tuple[str, str], ...]
    payload: tuple[tuple[str, Any], ...]

    def __post_init__(self) -> None:
        validate_non_empty_str(self.id, "id")
        if not isinstance(self.source, SourceRef):
            raise TypeError(f"source must be a SourceRef, got {type(self.source).__name__}")
        if not isinstance(self.record_kind, RecordKind):
            raise TypeError(
                f"record_kind must be a RecordKind, got {type(self.record_kind).__name__}"
            )
        validate_tz_datetime(self.observed_at, "observed_at")
        validate_tz_datetime(self.collected_at, "collected_at")
        if not isinstance(self.quality, EvidenceQuality):
            raise TypeError(
                f"quality must be an EvidenceQuality instance, got {type(self.quality).__name__}"
            )
        validate_str_pair_tuple(self.entity_references, "entity_references")
        validate_keyed_tuple(self.payload, "payload")

        # Note: collected_at < observed_at is NOT rejected. Clock skew between a
        # cloud provider and the collector is normal, and refusing such records
        # would drop real data. It is surfaced via collection_lag so a rule can
        # decide what a negative lag means.

    # --- Derived facts (no interpretation; scoring turns these into scores) ---

    def age_at(self, evaluation_time: datetime) -> timedelta:
        """How old the underlying fact is. Basis for freshness decay."""
        validate_tz_datetime(evaluation_time, "evaluation_time")
        return evaluation_time - self.observed_at

    def staleness_at(self, evaluation_time: datetime) -> timedelta:
        """How long since this pipeline last learned anything. Basis for blind-spot detection."""
        validate_tz_datetime(evaluation_time, "evaluation_time")
        return evaluation_time - self.collected_at

    @property
    def collection_lag(self) -> timedelta:
        """Pipeline delay between the fact occurring and being ingested. May be negative."""
        return self.collected_at - self.observed_at

    # --- Ergonomics over the hashable tuple representation ---

    def payload_dict(self) -> dict[str, Any]:
        return dict(self.payload)

    def references_dict(self) -> dict[str, str]:
        return dict(self.entity_references)


def canonical_payload(payload: tuple[tuple[str, Any], ...]) -> str:
    """
    Deterministic serialization used for content addressing.

    Sorted keys and a fixed separator so that two structurally identical payloads
    always produce the same string regardless of insertion order.
    """
    return json.dumps(
        dict(payload), sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=True
    )


def content_id(
    source: SourceRef,
    record_kind: RecordKind,
    observed_at: datetime,
    entity_references: tuple[tuple[str, str], ...],
    payload: tuple[tuple[str, Any], ...],
    prefix: str = "ev",
) -> str:
    """
    Derives a content-addressed Evidence id.

    Re-ingesting the same IAM dump produces identical ids, so deduplication is
    free and a RiskAssessment citing evidence_ids stays reproducible across runs
    -- which is what makes an assessment auditable rather than merely plausible.

    collected_at is excluded on purpose: re-collecting an unchanged fact should
    not mint a new id. Connectors whose source already has a stable id
    (CloudTrail's eventID, for instance) should use that instead.
    """
    material = "|".join(
        (
            str(source),
            record_kind.value,
            observed_at.isoformat(),
            canonical_payload(tuple(sorted(entity_references))),
            canonical_payload(payload),
        )
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:32]}"
