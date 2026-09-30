"""
The rule contract: what a detection is, and what it is obliged to return.

A rule is a pure function of (features, coverage) that either fires or does not.
When it fires it must say four things, and the separation between them is the
whole design:

    impact      how bad this is if the finding is true        (0-10)
    likelihood  how likely the finding is true of the world   (0-10)
    confidence  how much the *input evidence* can be trusted  (0-1)
    evidence    the records that made it fire                 (citations)

Splitting confidence out from impact and likelihood is what lets the engine say
"possible stale access, but we have not heard from this source in fourteen days"
instead of the far more dangerous "low risk". A weighted-sum scorer collapses
those into one number and structurally cannot distinguish them -- which is
exactly the failure `stale_connector_blind_spot` was written to catch.

Rules never construct a `RiskAssessment` and never see other rules. They observe
one identity and report one judgement; aggregation, ordering and the overall
score belong to the engine.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Protocol, Sequence, runtime_checkable

from app.common.validation import (
    validate_non_empty_str,
    validate_numeric,
    validate_tz_datetime,
)
from app.evidence.models import RecordKind
from app.graph.effective import EffectiveReach
from app.models.event import Event
from app.models.identity import Identity
from app.models.resource import Resource
from app.risk.baselines import PeerBaseline
from app.risk.coverage import CoverageSummary, EvidenceIndex
from app.risk.features import IdentityFeatures
from app.risk.models import RiskFactorAssessment, RiskFactorType, RiskSubject


@dataclass(frozen=True)
class RuleContext:
    """
    Everything a rule is allowed to look at.

    Deliberately not the `Estate`. A rule that could reach the whole estate
    would grow cross-identity logic, and cross-identity reasoning (peer-group
    baselines, access paths) is a different layer with different performance
    characteristics. Narrowing the context keeps every rule O(1) in the size of
    the estate and trivially unit-testable.

    `index` is carried rather than a pre-computed id list because a rule knows
    which records justify *its own* finding: a staleness rule cites the grant,
    a burst rule cites the failed logins. Citing everything would make
    `evidence_ids` useless as an explanation.
    """

    identity: Identity
    features: IdentityFeatures
    coverage: CoverageSummary
    evaluation_time: datetime
    resources: tuple[Resource, ...] = ()
    # This identity's own events, oldest first. Carried because rate and
    # sequence are not expressible as scalar features: "12 failed logins" is
    # the same number whether they fell in 40 minutes or 30 days, and
    # `failed_logins_spread_thin` exists to punish a rule that cannot tell
    # those apart. Still one identity's worth of data, so rules stay O(1) in
    # the size of the estate.
    events: tuple[Event, ...] = ()
    index: Optional[EvidenceIndex] = None
    # Precomputed once per estate by the engine, never built by a rule. It is
    # the only cross-identity fact a rule may read, and it is read by key, so
    # rules stay O(1) in estate size. None means "no baseline was computed"
    # (a single-identity assessment), and peer rules decline rather than guess.
    peers: Optional[PeerBaseline] = None
    # This identity's effective reach through the graph, computed by the
    # engine -- never walked by a rule. Like `peers`, it is precomputed and
    # read for one identity only, so rules stay O(1) in estate size. None means
    # no walk was done, and graph rules decline rather than guess.
    reach: Optional[EffectiveReach] = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, Identity):
            raise TypeError(f"identity must be an Identity, got {type(self.identity).__name__}")
        if not isinstance(self.features, IdentityFeatures):
            raise TypeError(
                f"features must be an IdentityFeatures, got {type(self.features).__name__}"
            )
        if not isinstance(self.coverage, CoverageSummary):
            raise TypeError(
                f"coverage must be a CoverageSummary, got {type(self.coverage).__name__}"
            )
        validate_tz_datetime(self.evaluation_time, "evaluation_time")
        if not isinstance(self.resources, tuple):
            raise TypeError(f"resources must be a tuple, got {type(self.resources).__name__}")
        if not isinstance(self.events, tuple):
            raise TypeError(f"events must be a tuple, got {type(self.events).__name__}")
        for ev in self.events:
            if ev.identity_id != self.identity.id:
                raise ValueError(
                    f"event {ev.id} belongs to '{ev.identity_id}', not "
                    f"'{self.identity.id}'"
                )
        if self.peers is not None and not isinstance(self.peers, PeerBaseline):
            raise TypeError(f"peers must be a PeerBaseline, got {type(self.peers).__name__}")
        if self.reach is not None:
            if not isinstance(self.reach, EffectiveReach):
                raise TypeError(
                    f"reach must be an EffectiveReach, got {type(self.reach).__name__}"
                )
            if self.reach.identity_id != self.identity.id:
                raise ValueError(
                    f"reach is for identity '{self.reach.identity_id}' but context "
                    f"identity is '{self.identity.id}'"
                )
        if self.coverage.identity_id != self.identity.id:
            raise ValueError(
                f"coverage is for identity '{self.coverage.identity_id}' but context "
                f"identity is '{self.identity.id}'"
            )

    def resource(self, resource_id: str) -> Optional[Resource]:
        """Unknown resources return None. Degrading silently is the contract here."""
        return next((r for r in self.resources if r.id == resource_id), None)

    def past_events(self) -> tuple[Event, ...]:
        """Events at or before evaluation_time, oldest first. Never the future."""
        return tuple(
            sorted(
                (e for e in self.events if e.timestamp <= self.evaluation_time),
                key=lambda e: e.timestamp,
            )
        )

    def cite(self, kind: RecordKind, entity_id: str) -> tuple[str, ...]:
        """Citation-ready evidence ids, or () when no index was supplied."""
        if self.index is None:
            return ()
        return self.index.evidence_ids_for(kind, entity_id)


@dataclass(frozen=True)
class RuleOutcome:
    """
    What a rule returns. Either a finding, or an explicit non-finding.

    A non-finding is a real, first-class result rather than `None`, because
    "this rule ran and declined to fire" and "this rule was never evaluated" are
    different facts, and the negative controls in the scenario set assert the
    former. `SCENARIOS` marks `should_fire=False` cases precisely so that "did
    not fire" is a tested outcome; returning None would erase the distinction.

    Validation is conditional: a non-finding carries no scores to validate, so
    it must leave every judgement field at its default. That stops a rule
    quietly returning `fired=False, impact=9.0` and leaving a reader to guess
    which field was authoritative.
    """

    fired: bool
    subject: Optional[RiskSubject] = None
    impact: float = 0.0
    likelihood: float = 0.0
    confidence: float = 0.0
    description: str = ""
    recommendation: str = ""
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.fired, bool):
            raise TypeError(f"fired must be a bool, got {type(self.fired).__name__}")

        if not isinstance(self.evidence_ids, tuple):
            raise TypeError(
                f"evidence_ids must be a tuple, got {type(self.evidence_ids).__name__}"
            )

        if not self.fired:
            # A non-finding must be inert in every respect.
            for name in ("impact", "likelihood", "confidence"):
                val = getattr(self, name)
                if val != 0.0:
                    raise ValueError(
                        f"a non-fired RuleOutcome must leave {name} at 0.0, got {val}"
                    )
            for name in ("description", "recommendation"):
                if getattr(self, name):
                    raise ValueError(f"a non-fired RuleOutcome must leave {name} empty")
            if self.subject is not None:
                raise ValueError("a non-fired RuleOutcome must leave subject as None")
            if self.evidence_ids:
                raise ValueError("a non-fired RuleOutcome must leave evidence_ids empty")
            return

        if not isinstance(self.subject, RiskSubject):
            raise TypeError(
                f"a fired RuleOutcome requires a RiskSubject, got {type(self.subject).__name__}"
            )
        validate_numeric(self.impact, "impact", 0.0, 10.0)
        validate_numeric(self.likelihood, "likelihood", 0.0, 10.0)
        validate_numeric(self.confidence, "confidence", 0.0, 1.0)
        validate_non_empty_str(self.description, "description")
        validate_non_empty_str(self.recommendation, "recommendation")
        for idx, evid in enumerate(self.evidence_ids):
            validate_non_empty_str(evid, f"evidence_ids[{idx}]")

    @classmethod
    def no_finding(cls) -> "RuleOutcome":
        """The canonical non-finding. Rules should return this rather than None."""
        return cls(fired=False)

    def to_assessment(self, rule_id: str, factor_type: RiskFactorType) -> RiskFactorAssessment:
        """
        Promotes a fired outcome to the engine's output DTO.

        The assessment id is derived from (rule, subject) rather than generated,
        so two runs over identical evidence produce byte-identical assessments.
        A random id would make diffing two assessments impossible and would
        undermine the same reproducibility guarantee `content_id` provides for
        evidence.
        """
        if not self.fired:
            raise ValueError("cannot promote a non-fired RuleOutcome to a RiskFactorAssessment")
        validate_non_empty_str(rule_id, "rule_id")
        if not isinstance(factor_type, RiskFactorType):
            raise TypeError(
                f"factor_type must be a RiskFactorType, got {type(factor_type).__name__}"
            )
        assert self.subject is not None  # guaranteed by __post_init__ when fired

        return RiskFactorAssessment(
            id=f"{rule_id}:{self.subject.subject_type.value}:{self.subject.subject_id}",
            factor_type=factor_type,
            subject=self.subject,
            impact=self.impact,
            likelihood=self.likelihood,
            confidence=self.confidence,
            evidence_ids=self.evidence_ids,
            description=self.description,
            recommendation=self.recommendation,
        )


@runtime_checkable
class Rule(Protocol):
    """
    A detection, expressed structurally so rules never inherit from the engine.

    `rule_id` is stable and versioned by the author, not derived from the class
    name: renaming a class must not silently change the id that appears in
    `RiskFactorAssessment.id` and in every stored assessment citing it.

    A rule must not raise. An exception mid-run would lose every finding from
    the rules that follow it, which is the same "one bad row sinks the batch"
    failure the normalizer was built to avoid. The engine will enforce this, but
    rules should not rely on being rescued.
    """

    rule_id: str
    factor_type: RiskFactorType

    def evaluate(self, ctx: RuleContext) -> RuleOutcome:
        ...


def assess(rule: Rule, ctx: RuleContext) -> Optional[RiskFactorAssessment]:
    """Convenience: evaluate a rule and promote it, or None when it declines."""
    outcome = rule.evaluate(ctx)
    if not isinstance(outcome, RuleOutcome):
        raise TypeError(
            f"rule '{getattr(rule, 'rule_id', rule)}' returned "
            f"{type(outcome).__name__}, expected RuleOutcome"
        )
    if not outcome.fired:
        return None
    return outcome.to_assessment(rule.rule_id, rule.factor_type)


def assess_all(
    rules: Sequence[Rule], ctx: RuleContext
) -> tuple[RiskFactorAssessment, ...]:
    """Runs every rule in order and returns the findings that fired."""
    out: list[RiskFactorAssessment] = []
    for rule in rules:
        result = assess(rule, ctx)
        if result is not None:
            out.append(result)
    return tuple(out)
