"""
Orchestration: estate in, RiskAssessment per identity out.

The engine owns three things rules are deliberately not allowed to own --
running them safely, suppressing findings we cannot trust, and combining what
survives into one score.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Sequence

from app.common.validation import validate_tz_datetime
from app.models.identity import Identity, IdentityType
from app.risk.baselines import PeerBaseline
from app.risk.coverage import CoverageAnalyzer, CoverageSummary, EvidenceIndex
from app.risk.detections import ALL_RULES
from app.risk.features import FeatureExtractor
from app.risk.models import RiskAssessment, RiskFactorAssessment
from app.risk.rules import Rule, RuleContext, RuleOutcome
from app.risk import scoring


@dataclass(frozen=True)
class IdentityResult:
    """
    One identity's assessment, plus what the engine chose not to report.

    Suppressed findings are carried rather than dropped. A finding held back
    for low confidence is a statement about our own coverage, and an engine
    that silently discards those cannot tell an operator the difference between
    "nothing to see" and "we cannot see".
    """

    identity_id: str
    assessment: RiskAssessment
    coverage: CoverageSummary
    suppressed: tuple[RiskFactorAssessment, ...] = ()
    rule_errors: tuple[tuple[str, str], ...] = ()


def is_assessed(identity: Identity) -> bool:
    """
    Whether the per-identity rules judge this identity as a subject.

    Roles are not, yet. Nobody logs in as a role -- activity is recorded against
    whoever assumed it -- so every role would look dormant to the staleness
    rules and fire on nothing. A role's grants are still real: they count
    against whoever can reach the role, which is the graph layer's job.
    """
    return identity.identity_type is not IdentityType.ROLE


class RiskEngine:
    def __init__(self, rules: Sequence[Rule] = ALL_RULES) -> None:
        self.rules = tuple(rules)

    def assess_identity(
        self,
        identity: Identity,
        resources: Sequence,
        events: Sequence,
        index: EvidenceIndex,
        evaluation_time: datetime,
        peers: Optional[PeerBaseline] = None,
    ) -> IdentityResult:
        validate_tz_datetime(evaluation_time, "evaluation_time")

        features = FeatureExtractor.extract_features(
            identity, resources, events, evaluation_time
        )
        coverage = CoverageAnalyzer.summarize(identity, events, index, evaluation_time)
        ctx = RuleContext(
            identity=identity,
            features=features,
            coverage=coverage,
            evaluation_time=evaluation_time,
            resources=tuple(resources),
            events=tuple(e for e in events if e.identity_id == identity.id),
            index=index,
            peers=peers,
        )

        reported: list[RiskFactorAssessment] = []
        suppressed: list[RiskFactorAssessment] = []
        errors: list[tuple[str, str]] = []

        for rule in self.rules:
            # A rule must not raise, but the engine must survive one that does:
            # an exception mid-run would lose every finding from the rules after
            # it, which is the same "one bad row sinks the batch" failure the
            # normalizer exists to prevent.
            try:
                outcome = rule.evaluate(ctx)
            except Exception as exc:  # noqa: BLE001 - isolation is the point
                errors.append((rule.rule_id, f"{type(exc).__name__}: {exc}"))
                continue
            if not isinstance(outcome, RuleOutcome) or not outcome.fired:
                continue
            assessment = outcome.to_assessment(rule.rule_id, rule.factor_type)
            if scoring.is_reportable(assessment.confidence):
                reported.append(assessment)
            else:
                suppressed.append(assessment)

        reported = self._dedupe(reported)
        overall = scoring.aggregate_risk(reported)

        return IdentityResult(
            identity_id=identity.id,
            assessment=RiskAssessment(
                overall_score=overall,
                risk_level=scoring.risk_level(overall),
                global_confidence=scoring.global_confidence(reported, coverage),
                dimension_scores=scoring.dimension_scores(reported),
                triggered_factors=tuple(reported),
                evaluated_at=evaluation_time,
                engine_version=scoring.ENGINE_VERSION,
                rule_version=scoring.RULE_VERSION,
            ),
            coverage=coverage,
            suppressed=tuple(suppressed),
            rule_errors=tuple(errors),
        )

    def assess_estate(
        self, estate, evaluation_time: datetime
    ) -> tuple[IdentityResult, ...]:
        # The cross-identity pre-pass: built once, read by key inside rules.
        peers = PeerBaseline.build(estate.identities)
        return tuple(
            self.assess_identity(
                identity, estate.resources, estate.events, estate, evaluation_time, peers
            )
            for identity in estate.identities
            if is_assessed(identity)
        )

    @staticmethod
    def _dedupe(
        assessments: list[RiskFactorAssessment],
    ) -> list[RiskFactorAssessment]:
        """
        One finding per (factor type, subject), keeping the strongest.

        Two staleness rules firing on the same identity describe one problem
        seen from two angles, not two independent risks. Letting both through
        would double-count it in the probabilistic aggregate and inflate the
        score for nothing.
        """
        best: dict[tuple, RiskFactorAssessment] = {}
        for a in assessments:
            key = (a.factor_type, a.subject)
            current = best.get(key)
            if current is None or scoring.weighted_risk(a) > scoring.weighted_risk(current):
                best[key] = a
        return sorted(best.values(), key=lambda a: scoring.weighted_risk(a), reverse=True)
