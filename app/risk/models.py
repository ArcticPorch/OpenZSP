"""
The risk vocabulary and the engine's output contract.

Evidence and EvidenceQuality deliberately do NOT live here: their fields
(source reliability, integrity, identity-mapping confidence) are ingestion
concerns, so they belong to app.evidence. Risk depends on evidence; evidence
knows nothing about risk.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from app.common.validation import (
    validate_non_empty_str,
    validate_numeric,
    validate_tz_datetime,
)


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskFactorType(Enum):
    EXCESSIVE_PRIVILEGE = "EXCESSIVE_PRIVILEGE"
    STALE_ACCESS = "STALE_ACCESS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    ANOMALOUS_BEHAVIOR = "ANOMALOUS_BEHAVIOR"
    EXTERNAL_EXPOSURE = "EXTERNAL_EXPOSURE"
    EXCESSIVE_BLAST_RADIUS = "EXCESSIVE_BLAST_RADIUS"
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
    # Several event-based findings on one identity close together in time:
    # one incident, not coincidences. Raised by the engine's sequence stage
    # (`app/risk/sequences.py`), never by a rule.
    MULTI_STAGE_SEQUENCE = "MULTI_STAGE_SEQUENCE"


class RiskSubjectType(Enum):
    IDENTITY = "identity"
    RESOURCE = "resource"
    PERMISSION = "permission"
    ACCESS_GRANT = "access_grant"
    ACCESS_PATH = "access_path"
    EVENT = "event"


# --- Domain and Value Objects ---

@dataclass(frozen=True)
class RiskSubject:
    subject_type: RiskSubjectType
    subject_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.subject_type, RiskSubjectType):
            raise TypeError(f"subject_type must be a RiskSubjectType, got {type(self.subject_type).__name__}")
        validate_non_empty_str(self.subject_id, "subject_id")


@dataclass(frozen=True)
class RiskFactorAssessment:
    id: str
    factor_type: RiskFactorType
    subject: RiskSubject
    impact: float
    likelihood: float
    confidence: float
    evidence_ids: tuple[str, ...]
    description: str
    recommendation: str

    def __post_init__(self) -> None:
        validate_non_empty_str(self.id, "id")
        if not isinstance(self.factor_type, RiskFactorType):
            raise TypeError(f"factor_type must be a RiskFactorType, got {type(self.factor_type).__name__}")
        if not isinstance(self.subject, RiskSubject):
            raise TypeError(f"subject must be a RiskSubject instance, got {type(self.subject).__name__}")

        validate_numeric(self.impact, "impact", 0.0, 10.0)
        validate_numeric(self.likelihood, "likelihood", 0.0, 10.0)
        validate_numeric(self.confidence, "confidence", 0.0, 1.0)

        # Validate evidence_ids structure: tuple[str, ...]
        if not isinstance(self.evidence_ids, tuple):
            raise TypeError(f"evidence_ids must be a tuple, got {type(self.evidence_ids).__name__}")
        for idx, evid_id in enumerate(self.evidence_ids):
            validate_non_empty_str(evid_id, f"evidence_ids[{idx}]")

        validate_non_empty_str(self.description, "description")
        validate_non_empty_str(self.recommendation, "recommendation")


@dataclass(frozen=True)
class RiskAssessment:
    overall_score: float
    risk_level: RiskLevel
    global_confidence: float
    dimension_scores: tuple[tuple[str, float], ...]
    triggered_factors: tuple[RiskFactorAssessment, ...]
    evaluated_at: datetime
    engine_version: str
    rule_version: str

    def __post_init__(self) -> None:
        validate_numeric(self.overall_score, "overall_score", 0.0, 100.0)
        if not isinstance(self.risk_level, RiskLevel):
            raise TypeError(f"risk_level must be a RiskLevel, got {type(self.risk_level).__name__}")
        validate_numeric(self.global_confidence, "global_confidence", 0.0, 1.0)

        # Validate dimension_scores structure: tuple[tuple[str, float], ...]
        if not isinstance(self.dimension_scores, tuple):
            raise TypeError(f"dimension_scores must be a tuple, got {type(self.dimension_scores).__name__}")
        for idx, item in enumerate(self.dimension_scores):
            if not isinstance(item, tuple) or len(item) != 2:
                raise TypeError(f"dimension_scores[{idx}] must be a tuple of length 2, got {item}")
            dim_name, dim_score = item
            validate_non_empty_str(dim_name, f"dimension_scores[{idx}][0] (name)")
            validate_numeric(dim_score, f"dimension_scores[{idx}][1] (score) for '{dim_name}'", 0.0, 100.0)

        # Validate triggered_factors structure: tuple[RiskFactorAssessment, ...]
        if not isinstance(self.triggered_factors, tuple):
            raise TypeError(f"triggered_factors must be a tuple, got {type(self.triggered_factors).__name__}")
        for idx, tf in enumerate(self.triggered_factors):
            if not isinstance(tf, RiskFactorAssessment):
                raise TypeError(
                    f"triggered_factors[{idx}] must be a RiskFactorAssessment instance, got {type(tf).__name__}"
                )

        validate_tz_datetime(self.evaluated_at, "evaluated_at")
        validate_non_empty_str(self.engine_version, "engine_version")
        validate_non_empty_str(self.rule_version, "rule_version")
