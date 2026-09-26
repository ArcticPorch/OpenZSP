from datetime import datetime, timezone
import pytest
from app.risk.models import (
    RiskLevel,
    RiskFactorType,
    RiskSubjectType,
    RiskSubject,
    RiskFactorAssessment,
    RiskAssessment,
)


def test_valid_risk_subject_construction():
    subj = RiskSubject(subject_type=RiskSubjectType.IDENTITY, subject_id="id_1")
    assert subj.subject_type == RiskSubjectType.IDENTITY
    assert subj.subject_id == "id_1"


def test_risk_subject_invalid_inputs():
    with pytest.raises(TypeError):
        # Invalid type
        RiskSubject(subject_type="identity", subject_id="id_1")  # type: ignore

    with pytest.raises(ValueError):
        # Empty id
        RiskSubject(subject_type=RiskSubjectType.IDENTITY, subject_id="")

    with pytest.raises(ValueError):
        # Whitespace id
        RiskSubject(subject_type=RiskSubjectType.IDENTITY, subject_id="   ")


def test_risk_factor_assessment_validation():
    subj = RiskSubject(subject_type=RiskSubjectType.IDENTITY, subject_id="alice")

    # Valid
    rfa = RiskFactorAssessment(
        id="rfa_1",
        factor_type=RiskFactorType.EXCESSIVE_PRIVILEGE,
        subject=subj,
        impact=8.5,
        likelihood=5.0,
        confidence=0.9,
        evidence_ids=("ev_1",),
        description="Excessive access rights",
        recommendation="Revoke permission",
    )
    assert rfa.impact == 8.5

    # Out of range impact
    with pytest.raises(ValueError):
        RiskFactorAssessment(
            id="rfa_1",
            factor_type=RiskFactorType.EXCESSIVE_PRIVILEGE,
            subject=subj,
            impact=11.0,
            likelihood=5.0,
            confidence=0.9,
            evidence_ids=("ev_1",),
            description="Excessive access rights",
            recommendation="Revoke permission",
        )


def test_risk_assessment_validation():
    subj = RiskSubject(subject_type=RiskSubjectType.IDENTITY, subject_id="alice")
    rfa = RiskFactorAssessment(
        id="rfa_1",
        factor_type=RiskFactorType.EXCESSIVE_PRIVILEGE,
        subject=subj,
        impact=8.5,
        likelihood=5.0,
        confidence=0.9,
        evidence_ids=("ev_1",),
        description="Excessive access rights",
        recommendation="Revoke permission",
    )

    # Valid RiskAssessment
    ra = RiskAssessment(
        overall_score=75.0,
        risk_level=RiskLevel.HIGH,
        global_confidence=0.9,
        dimension_scores=(("privilege", 85.0),),
        triggered_factors=(rfa,),
        evaluated_at=datetime.now(timezone.utc),
        engine_version="1.0.0",
        rule_version="1.0.0",
    )
    assert ra.overall_score == 75.0

    # Invalid dimension score value
    with pytest.raises(TypeError):
        RiskAssessment(
            overall_score=75.0,
            risk_level=RiskLevel.HIGH,
            global_confidence=0.9,
            dimension_scores=(("privilege", True),),  # boolean  # type: ignore
            triggered_factors=(rfa,),
            evaluated_at=datetime.now(timezone.utc),
            engine_version="1.0.0",
            rule_version="1.0.0",
        )


def test_immutability():
    subj = RiskSubject(subject_type=RiskSubjectType.IDENTITY, subject_id="alice")
    with pytest.raises(AttributeError):
        subj.subject_id = "bob"  # type: ignore
