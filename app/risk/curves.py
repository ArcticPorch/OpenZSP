"""
Tuning curves: the calibrated thresholds, drawn from TRAIN-only sweeps.

One small panel per threshold. The line is the number of TRAIN labels the
engine gets wrong at each value; the shaded band is the plateau where it gets
every one right; the solid marker is the value in use, the thin one the value
it replaced. Rendered as a self-contained SVG with no dependencies, so the
README can embed it and the only third-party requirement stays pytest.

Regenerate after any calibration change:

    ./venv/Scripts/python.exe -m app.main --curves docs/tuning_curves.svg
"""

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Sequence
from xml.sax.saxutils import escape

from app.risk import calibration


@dataclass(frozen=True)
class Curve:
    name: str
    values: tuple[float, ...]
    previous: Optional[float] = None
    log_x: bool = False


# The five thresholds calibration has touched, with the value each replaced.
CURVES: tuple[Curve, ...] = (
    Curve("CADENCE_TOLERANCE", tuple(round(0.5 + 0.05 * i, 2) for i in range(35)), previous=1.5),
    Curve("MIN_CADENCE_GAPS", (1, 2, 3, 4, 5), previous=3),
    Curve(
        "PEER_MAX_SAME_DEPT_SHARE",
        tuple(round(0.025 * i, 3) for i in range(21)),
        previous=0.25,
    ),
    Curve("MIN_REPORTING_CONFIDENCE", tuple(round(0.05 + 0.025 * i, 3) for i in range(29))),
    Curve(
        "BULK_READ_BASELINE_MULTIPLIER",
        (1, 1.2, 1.4, 1.6, 1.7, 1.8, 2, 2.5, 3, 3.5, 4, 5, 6, 6.5, 7, 8, 10),
        log_x=True,
    ),
)

# Panel geometry (px, in the SVG's own coordinate space).
COLS, PANEL_W, PANEL_H = 3, 300, 210
PAD_L, PAD_R, PAD_T, PAD_B = 34, 16, 46, 34

STYLE = """
.viz-root { --surface-1:#fcfcfb; --text-primary:#0b0b0b; --text-secondary:#52514e;
  --muted:#898781; --grid:#e1e0d9; --axis:#c3c2b7; --series-1:#2a78d6; --band:#cde2fb; }
@media (prefers-color-scheme: dark) {
  .viz-root { --surface-1:#1a1a19; --text-primary:#ffffff; --text-secondary:#c3c2b7;
    --muted:#898781; --grid:#2c2c2a; --axis:#383835; --series-1:#3987e5; --band:#104281; }
}
text { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
.title { font-size:12px; font-weight:600; fill:var(--text-primary); }
.sub { font-size:11px; fill:var(--text-secondary); }
.tick { font-size:10px; fill:var(--muted); font-variant-numeric: tabular-nums; }
.lbl { font-size:10px; fill:var(--text-primary); font-weight:600; }
.lbl-muted { font-size:10px; fill:var(--muted); }
"""


def _fmt(v: float) -> str:
    return f"{v:g}"


def _panel(curve: Curve, points, current, x0: float, y0: float) -> list[str]:
    w = PANEL_W - PAD_L - PAD_R
    h = PANEL_H - PAD_T - PAD_B
    vals = [p.value for p in points]
    errs = [len(p.false_positives) + len(p.false_negatives) for p in points]
    top = max(max(errs), 1)

    def fx(v: float) -> float:
        lo, hi = vals[0], vals[-1]
        if curve.log_x:
            lo, hi, v = math.log(lo), math.log(hi), math.log(v)
        return x0 + PAD_L + (v - lo) / (hi - lo) * w

    def fy(e: float) -> float:
        return y0 + PAD_T + h - e / top * h

    out = [
        f'<text class="title" x="{x0 + PAD_L}" y="{y0 + 18}">{escape(curve.name)}</text>',
    ]

    # Plateau band: the widest run of all-correct values.
    span = calibration.plateau(points)
    if span:
        a, b = fx(span[0]), fx(span[1])
        out.append(
            f'<rect x="{a:.1f}" y="{y0 + PAD_T}" width="{max(b - a, 2):.1f}" height="{h}" '
            f'fill="var(--band)" opacity="0.55"/>'
        )
        where = (
            f"only at {_fmt(span[0])}"
            if span[0] == span[1]
            else f"{_fmt(span[0])} – {_fmt(span[1])}"
        )
        out.append(f'<text class="sub" x="{x0 + PAD_L}" y="{y0 + 33}">all correct: {where}</text>')

    # Recessive grid: baseline plus the top error count.
    for e in (0, top):
        y = fy(e)
        stroke = "var(--axis)" if e == 0 else "var(--grid)"
        out.append(
            f'<line x1="{x0 + PAD_L}" x2="{x0 + PAD_L + w}" y1="{y:.1f}" y2="{y:.1f}" '
            f'stroke="{stroke}" stroke-width="1"/>'
        )
        out.append(f'<text class="tick" x="{x0 + PAD_L - 6}" y="{y + 3:.1f}" text-anchor="end">{e}</text>')

    # Step line: errors are constant between sampled values.
    d = []
    for i, (v, e) in enumerate(zip(vals, errs)):
        x, y = fx(v), fy(e)
        if i == 0:
            d.append(f"M{x:.1f},{y:.1f}")
        else:
            d.append(f"H{x:.1f}V{y:.1f}")
    out.append(
        f'<path d="{" ".join(d)}" fill="none" stroke="var(--series-1)" stroke-width="2" '
        f'stroke-linejoin="round" stroke-linecap="round"/>'
    )

    # Previous value (thin, muted) and current value (primary ink + marker).
    if curve.previous is not None and curve.previous != current:
        x = fx(curve.previous)
        out.append(
            f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{y0 + PAD_T}" y2="{y0 + PAD_T + h}" '
            f'stroke="var(--muted)" stroke-width="1"/>'
        )
        out.append(
            f'<text class="lbl-muted" x="{x + 4:.1f}" y="{y0 + PAD_T + 12}">was {_fmt(curve.previous)}</text>'
        )
    xc = fx(current)
    out.append(
        f'<line x1="{xc:.1f}" x2="{xc:.1f}" y1="{y0 + PAD_T}" y2="{y0 + PAD_T + h}" '
        f'stroke="var(--text-primary)" stroke-width="1.5"/>'
    )
    out.append(
        f'<circle cx="{xc:.1f}" cy="{fy(0):.1f}" r="4.5" fill="var(--series-1)" '
        f'stroke="var(--surface-1)" stroke-width="2"/>'
    )
    anchor = "end" if xc > x0 + PAD_L + w * 0.75 else "start"
    dx = -5 if anchor == "end" else 5
    out.append(
        f'<text class="lbl" x="{xc + dx:.1f}" y="{fy(0) - 8:.1f}" text-anchor="{anchor}">'
        f'{_fmt(current)}</text>'
    )

    # x ticks: the ends only; the marked values carry their own labels.
    for v, anchor in ((vals[0], "start"), (vals[-1], "end")):
        out.append(
            f'<text class="tick" x="{fx(v):.1f}" y="{y0 + PAD_T + h + 16}" '
            f'text-anchor="{anchor}">{_fmt(v)}</text>'
        )
    return out


def render_svg(anchor_time: datetime, curves: Sequence[Curve] = CURVES) -> str:
    rows = math.ceil((len(curves) + 1) / COLS)
    width, height = COLS * PANEL_W, rows * PANEL_H
    body: list[str] = []
    for i, curve in enumerate(curves):
        module = calibration._owner(curve.name)
        current = getattr(module, curve.name)
        points = calibration.sweep(curve.name, curve.values, anchor_time)
        body += _panel(curve, points, current, (i % COLS) * PANEL_W, (i // COLS) * PANEL_H)

    # The last cell is the key, so the encoding is never colour-alone.
    kx, ky = (len(curves) % COLS) * PANEL_W + PAD_L, (len(curves) // COLS) * PANEL_H + PAD_T
    body += [
        f'<text class="title" x="{kx}" y="{ky - 28}">How to read</text>',
        f'<line x1="{kx}" x2="{kx + 22}" y1="{ky - 4}" y2="{ky - 4}" stroke="var(--series-1)" stroke-width="2"/>',
        f'<text class="sub" x="{kx + 30}" y="{ky}">TRAIN labels wrong at that value</text>',
        f'<rect x="{kx}" y="{ky + 12}" width="22" height="12" fill="var(--band)" opacity="0.55"/>',
        f'<text class="sub" x="{kx + 30}" y="{ky + 22}">plateau: every TRAIN label right</text>',
        f'<line x1="{kx + 11}" x2="{kx + 11}" y1="{ky + 34}" y2="{ky + 50}" stroke="var(--text-primary)" stroke-width="1.5"/>',
        f'<text class="sub" x="{kx + 30}" y="{ky + 46}">value in use</text>',
        f'<line x1="{kx + 11}" x2="{kx + 11}" y1="{ky + 58}" y2="{ky + 74}" stroke="var(--muted)" stroke-width="1"/>',
        f'<text class="sub" x="{kx + 30}" y="{ky + 70}">value it replaced</text>',
        f'<text class="lbl-muted" x="{kx}" y="{ky + 100}">Sweeps run on TRAIN only.</text>',
        f'<text class="lbl-muted" x="{kx}" y="{ky + 114}">Multiplier axis is logarithmic.</text>',
    ]
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" class="viz-root" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" aria-labelledby="t d">'
        f'<title id="t">OpenZSP tuning curves</title>'
        f'<desc id="d">For each calibrated threshold, the number of TRAIN labels the engine '
        f'gets wrong as the threshold varies, with the all-correct plateau shaded and the '
        f'value in use marked.</desc>'
        f"<style>{STYLE}</style>"
        f'<rect width="{width}" height="{height}" rx="8" fill="var(--surface-1)"/>'
        + "".join(body)
        + "</svg>\n"
    )
