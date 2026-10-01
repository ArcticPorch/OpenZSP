"""
CLI entry point: run the pipeline over the labelled corpus and report quality.

    ./venv/Scripts/python.exe -m app.main             # train vs holdout vs fresh
    ./venv/Scripts/python.exe -m app.main --full      # whole-corpus detail
    ./venv/Scripts/python.exe -m app.main --train     # calibration detail
    ./venv/Scripts/python.exe -m app.main --holdout   # holdout detail (contaminated)
    ./venv/Scripts/python.exe -m app.main --fresh     # fresh detail -- read once per cycle
    ./venv/Scripts/python.exe -m app.main --findings  # per-identity assessments
    ./venv/Scripts/python.exe -m app.main --sweep NAME=v1,v2,...   # TRAIN only
    ./venv/Scripts/python.exe -m app.main --curves docs/tuning_curves.svg  # README chart
    ./venv/Scripts/python.exe -m app.main --paths petra   # one identity's routes and reach
    ./venv/Scripts/python.exe -m app.main --blast-radius  # ranked reach + choke points
"""

import sys
from datetime import datetime, timezone

from app.connectors.synthetic import SyntheticConnector
from app.normalize.normalizer import Normalizer
from app.risk.engine import RiskEngine
from app.connectors.synthetic import FRESH, HOLDOUT, TRAIN
from app.risk import calibration
from app.risk.evaluation import compare_splits, evaluate, format_report

# Fixed anchor: the corpus is deterministic, so the report must be too.
ANCHOR = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)


def show_findings() -> None:
    estate = _estate()
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


def run_sweep(spec: str) -> None:
    """`NAME=v1,v2,...` -> a TRAIN-only curve. Values parse as int, then float."""
    name, _, raw = spec.partition("=")

    def parse(v: str):
        for cast in (int, float):
            try:
                return cast(v)
            except ValueError:
                pass
        raise SystemExit(f"cannot parse sweep value {v!r}")

    values = [parse(v) for v in raw.split(",") if v]
    current = getattr(calibration._owner(name), name)
    print(calibration.format_sweep(name, calibration.sweep(name, values, ANCHOR), current))


def _estate():
    return Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())


def show_paths(identity_id: str) -> int:
    from app.risk.graph_report import format_paths

    try:
        print(format_paths(_estate(), identity_id, ANCHOR))
    except KeyError:
        print(f"unknown identity {identity_id!r}", file=sys.stderr)
        return 2
    return 0


def show_blast_radius() -> int:
    from app.risk.graph_report import format_blast_radius

    print(format_blast_radius(_estate(), ANCHOR))
    return 0


def write_curves(path: str) -> None:
    """Render the TRAIN-only tuning curves to an SVG file (used by the README)."""
    from pathlib import Path

    from app.risk.curves import render_svg

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_svg(ANCHOR), encoding="utf-8")
    print(f"wrote {out}")


def main() -> int:
    if "--paths" in sys.argv:
        idx = sys.argv.index("--paths")
        if idx + 1 >= len(sys.argv):
            raise SystemExit("usage: --paths <identity>")
        return show_paths(sys.argv[idx + 1])
    elif "--blast-radius" in sys.argv:
        return show_blast_radius()
    elif "--curves" in sys.argv:
        idx = sys.argv.index("--curves")
        write_curves(sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "docs/tuning_curves.svg")
    elif "--sweep" in sys.argv:
        idx = sys.argv.index("--sweep")
        if idx + 1 >= len(sys.argv):
            raise SystemExit("usage: --sweep NAME=v1,v2,...")
        run_sweep(sys.argv[idx + 1])
    elif "--findings" in sys.argv:
        show_findings()
    elif "--train" in sys.argv:
        print(format_report(evaluate(ANCHOR, split=TRAIN)))
    elif "--holdout" in sys.argv:
        print(format_report(evaluate(ANCHOR, split=HOLDOUT)))
    elif "--fresh" in sys.argv:
        print(format_report(evaluate(ANCHOR, split=FRESH)))
    elif "--full" in sys.argv:
        print(format_report(evaluate(ANCHOR)))
    else:
        print(compare_splits(ANCHOR))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
