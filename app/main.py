"""
CLI entry point: run the pipeline over the labelled corpus and report quality.

    ./venv/Scripts/python.exe -m app.main             # train vs holdout
    ./venv/Scripts/python.exe -m app.main --full      # whole-corpus detail
    ./venv/Scripts/python.exe -m app.main --train     # calibration detail
    ./venv/Scripts/python.exe -m app.main --holdout   # holdout detail
    ./venv/Scripts/python.exe -m app.main --findings  # per-identity assessments
"""

import sys
from datetime import datetime, timezone

from app.connectors.synthetic import SyntheticConnector
from app.normalize.normalizer import Normalizer
from app.risk.engine import RiskEngine
from app.connectors.synthetic import HOLDOUT, TRAIN
from app.risk.evaluation import compare_splits, evaluate, format_report

# Fixed anchor: the corpus is deterministic, so the report must be too.
ANCHOR = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)


def show_findings() -> None:
    estate = Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())
    results = RiskEngine().assess_estate(estate, ANCHOR)
    for result in sorted(results, key=lambda r: -r.assessment.overall_score):
        a = result.assessment
        if not a.triggered_factors and not result.suppressed:
            continue
        print(
            f"\n{result.identity_id:<22} {a.overall_score:5.1f}  "
            f"{a.risk_level.value.upper():<8} confidence {a.global_confidence:.2f}"
        )
        for factor in a.triggered_factors:
            print(f"    [{factor.factor_type.value}] {factor.description}")
            print(f"      -> {factor.recommendation}")
            print(f"      evidence: {len(factor.evidence_ids)} record(s)")
        for factor in result.suppressed:
            print(
                f"    [SUPPRESSED {factor.factor_type.value}] "
                f"confidence {factor.confidence:.2f} -- {factor.description}"
            )


def main() -> int:
    if "--findings" in sys.argv:
        show_findings()
    elif "--train" in sys.argv:
        print(format_report(evaluate(ANCHOR, split=TRAIN)))
    elif "--holdout" in sys.argv:
        print(format_report(evaluate(ANCHOR, split=HOLDOUT)))
    elif "--full" in sys.argv:
        print(format_report(evaluate(ANCHOR)))
    else:
        print(compare_splits(ANCHOR))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
