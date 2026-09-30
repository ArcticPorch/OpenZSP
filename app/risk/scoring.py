"""
Turning rule outcomes into scores. Every tunable constant in the engine lives here.

This is the only module allowed to hold an opinion about what a measurement
*means*. `features.py` and `coverage.py` report numbers; this file decides that
fourteen days of collection silence halves confidence twice over, and that two
medium findings compound rather than average. Keeping those judgements in one
file is what makes them tunable: calibration is editing constants here and
re-running the harness, not hunting thresholds scattered through rule bodies.

Aggregation is probabilistic, not additive. Two independent findings each at
0.5 risk combine to 0.75, not 1.0 and not 0.5 -- a second piece of evidence
should raise the estimate without either saturating it or being averaged away.
"""

from datetime import datetime
from typing import Optional, Sequence

from app.common.validation import validate_numeric
from app.models.resource import Exposure, Sensitivity
from app.risk.coverage import CoverageSummary
from app.risk.models import RiskFactorAssessment, RiskLevel

# --- Tunables --------------------------------------------------------------

# Collection silence halves confidence every week. Chosen so the 14-day gap in
# `stale_connector_blind_spot` lands at 0.25 -- two half-lives, enough to push
# that identity under the reporting floor without a rule special-casing it.
COLLECTION_STALENESS_HALF_LIFE_DAYS = 7.0

# Below this, a finding is suppressed rather than reported. The engine has to
# own this decision somewhere: a finding we cannot trust is not a low-risk
# finding, it is a coverage gap, and shipping it as an alert spends the
# operator's attention on our own blind spot. Suppressions are counted and
# reported separately so they stay visible instead of vanishing.
MIN_REPORTING_CONFIDENCE = 0.35

# Overall-score bands.
RISK_LEVEL_BANDS: tuple[tuple[float, RiskLevel], ...] = (
    (80.0, RiskLevel.CRITICAL),
    (55.0, RiskLevel.HIGH),
    (25.0, RiskLevel.MEDIUM),
    (0.0, RiskLevel.LOW),
)

# Blast radius: what one reachable resource is worth if this identity is
# compromised. weight = sensitivity x exposure x capability factor, summed over
# resources (see `blast_radius.py`). Deliberately a sum, not a saturating
# combination: blast radius exists to *rank* the identities that reach a lot,
# and 1 - prod(1 - p) puts everyone with two crown jewels at ~100. The bound is
# applied once, later -- a rule maps the sum to impact, and `aggregate_risk`
# saturates across findings.
#
# Roughly 3x per sensitivity level, so crown jewels dominate: admin on thirty
# LOW resources only equals admin on one CRITICAL resource, and reading thirty
# LOW dashboards is worth a fifth of that.
BLAST_SENSITIVITY_WEIGHT: dict[Sensitivity, float] = {
    Sensitivity.LOW: 1.0,
    Sensitivity.MEDIUM: 3.0,
    Sensitivity.HIGH: 10.0,
    Sensitivity.CRITICAL: 30.0,
}
# Resource-side reachability from outside. The identity side (`is_external`)
# is deliberately absent: it changes how *likely* compromise is, not how much
# a compromise reaches.
BLAST_EXPOSURE_MULTIPLIER: dict[Exposure, float] = {
    Exposure.INTERNAL: 1.0,
    Exposure.VPC_PEERED: 1.25,
    Exposure.PUBLIC: 1.5,
}
# What the capability lets an attacker do there. READ on a secret store is
# privileged: a secret is someone else's access.
BLAST_PRIVILEGED_FACTOR = 1.0
BLAST_WRITE_FACTOR = 0.5
BLAST_READ_FACTOR = 0.2

ENGINE_VERSION = "0.1.0"
RULE_VERSION = "2026.09.29"


# --- Confidence ------------------------------------------------------------


def freshness_factor(staleness_days: Optional[float]) -> float:
    """
    Exponential decay on how long since we last ingested anything.

    Decay rather than a cliff because trust in a silent source degrades
    continuously -- there is no moment at which a feed becomes worthless. A
    threshold would also make the metric discontinuous: a rule firing at 6.9
    days and vanishing at 7.1 is impossible to calibrate against.

    `None` means no activity evidence at all, which is maximum uncertainty
    rather than maximum freshness.
    """
    if staleness_days is None:
        return 0.0
    if staleness_days <= 0.0:
        return 1.0
    return 0.5 ** (staleness_days / COLLECTION_STALENESS_HALF_LIFE_DAYS)


def confidence_from_coverage(coverage: CoverageSummary) -> float:
    """
    How much the evidence behind an identity can be trusted, in 0..1.

    A product, not a mean. These factors are independent ways of being wrong --
    a partial feed, a misattributed principal, an unreliable source, a dead
    connector -- and any one of them being bad is sufficient to make the
    conclusion unsafe. Averaging would let three good factors rescue one fatal
    one, which is exactly the arithmetic that reports "all clear" while blind.
    """
    if not coverage.has_evidence:
        return 0.0
    return (
        # Semantic coverage sits alongside the collection factors because it is
        # the same kind of failure: an unclassified grant is access we cannot
        # reason about. An engine that ignored it would report confidently on
        # an identity whose permissions it does not understand.
        coverage.capability_coverage
        * coverage.min_completeness
        * coverage.min_identity_mapping_confidence
        * coverage.min_source_reliability
        * coverage.min_integrity_authenticity
        * freshness_factor(
            coverage.activity_collection_staleness_days
            if coverage.activity_collection_staleness_days is not None
            else coverage.max_collection_staleness_days
        )
    )


# --- Aggregation -----------------------------------------------------------


def factor_risk(impact: float, likelihood: float) -> float:
    """Normalised 0..1 risk for one finding, before confidence is applied."""
    validate_numeric(impact, "impact", 0.0, 10.0)
    validate_numeric(likelihood, "likelihood", 0.0, 10.0)
    return (impact / 10.0) * (likelihood / 10.0)


def weighted_risk(assessment: RiskFactorAssessment) -> float:
    """
    Risk discounted by how much we trust the evidence behind it.

    This is the one place confidence touches the score. It is deliberately a
    discount on the *contribution*, never a reduction of `impact` -- a finding
    we are unsure about is still just as bad if it turns out to be true, and
    folding uncertainty into impact would destroy that distinction on the way
    to the report.
    """
    return factor_risk(assessment.impact, assessment.likelihood) * assessment.confidence


def aggregate_risk(assessments: Sequence[RiskFactorAssessment]) -> float:
    """
    Combine findings probabilistically into an overall 0-100 score.

    `1 - prod(1 - r_i)`: the chance that at least one finding represents real
    exposure, if they were independent. They are not fully independent -- stale
    access and excessive privilege co-occur -- so this overstates slightly, and
    that is the acceptable direction for a privilege engine to err.

    A sum would saturate at 100 the moment three findings landed, making every
    badly-configured identity indistinguishable. A mean would let one clean
    dimension wash out a critical one.
    """
    if not assessments:
        return 0.0
    surviving = 1.0
    for a in assessments:
        surviving *= 1.0 - weighted_risk(a)
    return round((1.0 - surviving) * 100.0, 2)


def dimension_scores(
    assessments: Sequence[RiskFactorAssessment],
) -> tuple[tuple[str, float], ...]:
    """
    Per-factor-type scores, 0-100, worst finding wins within a dimension.

    Max rather than aggregate inside a dimension: two dormant grants are one
    staleness problem observed twice, not two independent risks, so compounding
    them would double-count the same underlying fact.
    """
    best: dict[str, float] = {}
    for a in assessments:
        key = a.factor_type.value
        best[key] = max(best.get(key, 0.0), weighted_risk(a) * 100.0)
    return tuple(sorted((k, round(v, 2)) for k, v in best.items()))


def global_confidence(
    assessments: Sequence[RiskFactorAssessment], coverage: CoverageSummary
) -> float:
    """
    How much the assessment as a whole can be trusted.

    Falls back to raw coverage confidence when nothing fired, so a clean report
    over a dead connector still says "we are not sure" rather than implying a
    confident all-clear.
    """
    if not assessments:
        return round(confidence_from_coverage(coverage), 4)
    return round(min(a.confidence for a in assessments), 4)


def risk_level(overall_score: float) -> RiskLevel:
    validate_numeric(overall_score, "overall_score", 0.0, 100.0)
    for threshold, level in RISK_LEVEL_BANDS:
        if overall_score >= threshold:
            return level
    return RiskLevel.LOW


def is_reportable(confidence: float) -> bool:
    """Whether a finding clears the confidence floor."""
    return confidence >= MIN_REPORTING_CONFIDENCE


def evaluated_at(evaluation_time: datetime) -> datetime:
    return evaluation_time
