"""
StackSentry Hex-Seal Badge
==========================

The signature StackSentry badge: a standalone hexagonal shield seal (the mark)
followed by a coloured grade pill (the data).

    [ ⬡ ]  [ SECURITY GRADE          B ]
     seal      stacksentry · verified

Design rationale
----------------
- The hexagon is deliberately SEPARATE from the pill. It is the recognisable
  StackSentry mark — it can stand alone as a favicon, avatar, or logo, and it
  is what makes the badge identifiable by silhouette before any text is read.
- A flat-top hexagon gives clean vertical side edges, so the seal reads as a
  crest/stamp rather than a generic polygon.
- A live pulsing dot on the seal is the "tell": an authentic badge served live
  from the StackSentry server breathes; a copied static screenshot freezes.
  (GitHub's Camo proxy strips animation, so on GitHub the shape identifies it
  and the verify-link proves it; the pulse is a bonus where animation is kept.)
- The grade letter sits large and bold on the right of the pill, colour-coded.

This module is pure rendering. The grade is supplied by the caller; trust,
scanning, and verification live in later layers.
"""

from __future__ import annotations
from html import escape

# ── Brand palette ───────────────────────────────────────────────────────────
SEAL_BG = "#0D1B2A"    # StackSentry navy — the seal fill
SEAL_EDGE = "#10B981"  # teal — seal border and shield glyph
TEAL = "#10B981"

# Grade → pill background + on-pill text colour.
GRADE_COLOURS = {
    "A": {"bg": "#16A34A", "sub": "#BBF7D0"},   # green
    "B": {"bg": "#2563EB", "sub": "#BFDBFE"},   # blue
    "C": {"bg": "#0E7490", "sub": "#A5F3FC"},   # teal
    "D": {"bg": "#D97706", "sub": "#FDE68A"},   # amber
    "F": {"bg": "#DC2626", "sub": "#FECACA"},   # red
}

STATE_COLOURS = {
    "unknown":    {"bg": "#6B7280", "sub": "#D1D5DB"},
    "stale":      {"bg": "#78716C", "sub": "#E7E5E4"},
    "error":      {"bg": "#991B1B", "sub": "#FECACA"},
    "unverified": {"bg": "#6B7280", "sub": "#D1D5DB"},
    "pending":    {"bg": "#0E7490", "sub": "#A5F3FC"},   # teal — scan in progress
}

# Rough character width for the pill's top/bottom label text at their sizes.
_CHAR_W_TOP = 6.4   # ~11px "SECURITY GRADE"
_CHAR_W_SUB = 5.0   # ~9px  "stacksentry · verified"


def _seal_svg(x: float, y: float, size: float, *, live: bool) -> str:
    """
    Render the standalone hexagonal shield seal at (x, y).

    The seal is a flat-top hexagon containing a small shield-with-check glyph,
    optionally with a live pulsing verification dot in the top-right.
    """
    r = size / 2
    cx = x + r
    cy = y + r
    # Flat-top hexagon points (rotation 30 from pointy-top).
    import math
    pts = []
    for i in range(6):
        a = math.radians(60 * i + 30)
        pts.append((round(cx + r * math.cos(a), 2), round(cy + r * math.sin(a), 2)))
    hexpath = "M" + " L".join(f"{px} {py}" for px, py in pts) + " Z"

    # Shield glyph inside the hexagon, scaled to the seal size.
    # Shield occupies the central ~55% of the hexagon.
    s = size * 0.42
    sx = cx - s / 2
    sy = cy - s / 2 - size * 0.02
    shield = (
        f'<path d="M{sx} {sy+s*0.1} '
        f'L{sx} {sy+s*0.55} '
        f'Q{sx} {sy+s*0.85} {sx+s/2} {sy+s} '
        f'Q{sx+s} {sy+s*0.85} {sx+s} {sy+s*0.55} '
        f'L{sx+s} {sy+s*0.1} Z" '
        f'fill="{SEAL_EDGE}" fill-opacity="0.16" stroke="{SEAL_EDGE}" stroke-width="1.3"/>'
    )
    # Checkmark inside the shield.
    check = (
        f'<path d="M{sx+s*0.28} {sy+s*0.5} '
        f'L{sx+s*0.45} {sy+s*0.66} '
        f'L{sx+s*0.74} {sy+s*0.32}" '
        f'fill="none" stroke="{SEAL_EDGE}" stroke-width="1.5" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
    )

    # Live verification dot (top-right vertex area).
    dot = ""
    if live:
        dx, dy = pts[5][0] - 1.5, pts[5][1] + 1.5  # near top-right vertex
        dot = (
            f'<circle cx="{dx}" cy="{dy}" r="2.4" fill="{SEAL_EDGE}">'
            f'<animate attributeName="opacity" values="1;0.3;1" '
            f'dur="2s" repeatCount="indefinite"/></circle>'
        )

    return (
        f'<path d="{hexpath}" fill="{SEAL_BG}" stroke="{SEAL_EDGE}" stroke-width="1.2"/>'
        f'{shield}{check}{dot}'
    )


def render_seal_badge(grade: str, *, score: float | None = None,
                      state: str | None = None, live: bool = True) -> str:
    """
    Render the full StackSentry hex-seal badge.

    Parameters
    ----------
    grade : str
        Grade letter A–F. Ignored when `state` is set.
    score : float, optional
        Percentage score, shown small under the grade when present.
    state : str, optional
        "unknown" | "stale" | "error" | "unverified" — overrides the grade.
    live : bool
        Whether to include the pulsing verification dot (default True).

    Returns
    -------
    str  A complete <svg> document.
    """
    if state:
        colours = STATE_COLOURS.get(state, STATE_COLOURS["unknown"])
        grade_char = "?"
        top_label = "SECURITY GRADE"
        sub_label = f"stacksentry · {state}"
    else:
        g = (grade or "").upper().strip()
        if g in GRADE_COLOURS:
            colours = GRADE_COLOURS[g]
            grade_char = g
            top_label = "SECURITY GRADE"
            sub_label = "stacksentry · verified"
        else:
            colours = STATE_COLOURS["unknown"]
            grade_char = "?"
            top_label = "SECURITY GRADE"
            sub_label = "stacksentry · unknown"

    height = 30
    seal_size = 28
    seal_x = 1
    seal_y = (height - seal_size) / 2
    gap = 6                      # space between seal and pill

    # Pill sizing — width driven by the longer of the two label lines plus the
    # grade cell on the right.
    top_w = len(top_label) * _CHAR_W_TOP
    sub_w = len(sub_label) * _CHAR_W_SUB
    label_w = max(top_w, sub_w)
    label_pad = 12
    grade_cell_w = 30            # room for the big grade letter (and score)

    pill_x = seal_x + seal_size + gap
    pill_w = int(label_pad + label_w + 8 + grade_cell_w)
    pill_h = 26
    pill_y = (height - pill_h) / 2
    pill_r = 6

    total_w = int(pill_x + pill_w + 2)

    bg = colours["bg"]
    sub_col = colours["sub"]

    # Text positions inside the pill.
    text_x = pill_x + label_pad
    top_y = pill_y + 11
    sub_y = pill_y + 20
    grade_cx = pill_x + pill_w - grade_cell_w / 2 - 2
    grade_y = pill_y + pill_h / 2 + 6

    top_lbl = escape(top_label)
    sub_lbl = escape(sub_label)
    gc = escape(grade_char)

    seal = _seal_svg(seal_x, seal_y, seal_size, live=live)

    # A subtle divider between the label area and the grade cell.
    divider_x = pill_x + pill_w - grade_cell_w - 4

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{height}" role="img" aria-label="StackSentry security grade: {gc}">
  <title>StackSentry security grade: {gc}</title>
  {seal}
  <rect x="{pill_x}" y="{pill_y}" width="{pill_w}" height="{pill_h}" rx="{pill_r}" fill="{bg}"/>
  <line x1="{divider_x}" y1="{pill_y + 5}" x2="{divider_x}" y2="{pill_y + pill_h - 5}" stroke="#FFFFFF" stroke-opacity="0.25" stroke-width="1"/>
  <g font-family="Inter,Segoe UI,Verdana,DejaVu Sans,sans-serif">
    <text x="{text_x}" y="{top_y}" fill="#FFFFFF" font-size="10" font-weight="700" letter-spacing="0.5">{top_lbl}</text>
    <text x="{text_x}" y="{sub_y}" fill="{sub_col}" font-size="9" font-weight="500">{sub_lbl}</text>
    <text x="{grade_cx}" y="{grade_y}" fill="#FFFFFF" font-size="17" font-weight="800" text-anchor="middle">{gc}</text>
  </g>
</svg>'''
    return svg
