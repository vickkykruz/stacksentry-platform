"""
StackSentry Badge Renderer
==========================

Pure SVG generation for security grade badges. No database, no scanning —
this module only turns (domain, grade, score) into an SVG string.

Design notes:
- Two-cell layout: a dark "shield" label cell + a coloured grade cell.
- Grade cell colour is driven by the grade letter, matching the StackSentry
  slate/teal palette used across the product (docs, social banner, viva deck).
- Font stack uses the same family GitHub's own badges use (Verdana / DejaVu Sans)
  so the badge sits naturally next to shields.io badges in a README.
- Text is rendered with a subtle shadow (the standard shields.io technique)
  for legibility on any background.
"""

from __future__ import annotations
from html import escape

# ── Brand palette ───────────────────────────────────────────────────────────
# The label cell is always StackSentry navy. The grade cell colour encodes the
# grade, using accessible foreground/background pairs.
LABEL_BG = "#0D1B2A"   # StackSentry navy

GRADE_COLOURS = {
    "A": {"bg": "#16A34A", "fg": "#FFFFFF"},   # green  — excellent
    "B": {"bg": "#2563EB", "fg": "#FFFFFF"},   # blue   — good
    "C": {"bg": "#0E7490", "fg": "#FFFFFF"},   # teal   — acceptable
    "D": {"bg": "#D97706", "fg": "#FFFFFF"},   # amber  — poor
    "F": {"bg": "#DC2626", "fg": "#FFFFFF"},   # red    — failing
}

# States where no valid grade exists.
STATE_COLOURS = {
    "unknown":  {"bg": "#6B7280", "fg": "#FFFFFF"},   # grey
    "stale":    {"bg": "#78716C", "fg": "#FFFFFF"},   # warm grey
    "error":    {"bg": "#991B1B", "fg": "#FFFFFF"},   # dark red
    "unverified": {"bg": "#6B7280", "fg": "#FFFFFF"},
}

LABEL_TEXT = "security"

# Approximate character width in the 11px Verdana-like face shields.io uses.
# This lets us size cells to fit their text without measuring fonts at runtime.
_CHAR_W = 6.6
_PADDING = 10  # px of horizontal padding inside each cell


def _text_width(text: str) -> float:
    """Rough pixel width of a string at 11px in the badge font."""
    return len(text) * _CHAR_W


def _cell_width(text: str) -> int:
    return int(_text_width(text) + _PADDING * 2)


def render_badge(grade: str, *, score: float | None = None,
                 state: str | None = None) -> str:
    """
    Render a security grade badge as an SVG string.

    Parameters
    ----------
    grade : str
        Single-letter grade A–F. Ignored when `state` is set.
    score : float, optional
        Percentage score. When provided and a real grade exists, the right
        cell reads e.g. "B  82%". When None, it reads just the grade letter.
    state : str, optional
        One of "unknown", "stale", "error", "unverified". When set, overrides
        the grade and shows a neutral state label instead of a letter.

    Returns
    -------
    str
        A complete <svg>...</svg> document.
    """
    # Decide right-cell text and colour.
    if state:
        colours = STATE_COLOURS.get(state, STATE_COLOURS["unknown"])
        right_text = state
    else:
        g = (grade or "").upper().strip()
        colours = GRADE_COLOURS.get(g, STATE_COLOURS["unknown"])
        if g not in GRADE_COLOURS:
            right_text = "unknown"
        elif score is not None:
            right_text = f"{g}  {score:.0f}%"
        else:
            right_text = g

    left_w = _cell_width(LABEL_TEXT)
    right_w = _cell_width(right_text)
    total_w = left_w + right_w
    height = 20

    # Text anchor x-positions (centre of each cell). Multiplied by 10 because
    # we use a 10x scaled textLength coordinate trick for crisp rendering.
    left_cx = left_w / 2 * 10
    right_cx = (left_w + right_w / 2) * 10
    left_tl = _text_width(LABEL_TEXT) * 10
    right_tl = _text_width(right_text) * 10

    label = escape(LABEL_TEXT)
    value = escape(right_text)
    bg = colours["bg"]
    fg = colours["fg"]

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{total_w}" height="{height}" role="img" aria-label="{label}: {value}">
  <title>{label}: {value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_w}" height="{height}" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{left_w}" height="{height}" fill="{LABEL_BG}"/>
    <rect x="{left_w}" width="{right_w}" height="{height}" fill="{bg}"/>
    <rect width="{total_w}" height="{height}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110" text-rendering="geometricPrecision">
    <!-- shield glyph -->
    <text x="{left_cx - _text_width(label)*10/2 - 30}" y="150" fill="#10B981" font-size="120" transform="scale(.1)">&#128737;</text>
    <text aria-hidden="true" x="{left_cx + 55}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{left_tl - 60}">{label}</text>
    <text x="{left_cx + 55}" y="140" transform="scale(.1)" fill="#fff" textLength="{left_tl - 60}">{label}</text>
    <text aria-hidden="true" x="{right_cx}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{right_tl}">{value}</text>
    <text x="{right_cx}" y="140" transform="scale(.1)" fill="{fg}" textLength="{right_tl}">{value}</text>
  </g>
</svg>'''
    return svg


def render_flat_badge(grade: str, *, score: float | None = None,
                      state: str | None = None) -> str:
    """
    A flatter, more modern badge variant — no gloss gradient, rounded corners,
    a shield glyph, and a bold grade cell. This is the StackSentry "signature"
    style, distinct from stock shields.io badges so it is recognisable.

    Layout (left → right):
      [ 🛡  security ][  GRADE · SCORE  ]
        navy label cell     coloured grade cell
    """
    if state:
        colours = STATE_COLOURS.get(state, STATE_COLOURS["unknown"])
        right_text = state
    else:
        g = (grade or "").upper().strip()
        colours = GRADE_COLOURS.get(g, STATE_COLOURS["unknown"])
        if g not in GRADE_COLOURS:
            right_text = "unknown"
        elif score is not None:
            right_text = f"{g} \u00b7 {score:.0f}%"
        else:
            right_text = g

    height = 22
    radius = 4

    # Left cell layout — measured, not guessed.
    shield_glyph_w = 16          # visual width the shield occupies
    gap_after_shield = 4         # space between shield and label text
    edge_pad = 8                 # padding at the outer edges

    label_text_w = _text_width(LABEL_TEXT)
    left_w = int(edge_pad + shield_glyph_w + gap_after_shield + label_text_w + edge_pad)

    # Right cell layout — centre the value text with even padding.
    value_text_w = _text_width(right_text)
    right_w = int(edge_pad + value_text_w + edge_pad)

    total_w = left_w + right_w

    # X positions inside the left cell.
    shield_x = edge_pad
    label_x = edge_pad + shield_glyph_w + gap_after_shield
    # X centre of the right cell.
    value_cx = left_w + right_w / 2

    label = escape(LABEL_TEXT)
    value = escape(right_text)
    bg = colours["bg"]
    fg = colours["fg"]

    # Baseline y for 11px text in a 22px tall badge.
    baseline = 15

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{height}" role="img" aria-label="{label}: {value}">
  <title>StackSentry {label}: {value}</title>
  <clipPath id="rr">
    <rect width="{total_w}" height="{height}" rx="{radius}" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#rr)">
    <rect width="{left_w}" height="{height}" fill="{LABEL_BG}"/>
    <rect x="{left_w}" width="{right_w}" height="{height}" fill="{bg}"/>
  </g>
  <g font-family="Inter,Segoe UI,Verdana,DejaVu Sans,sans-serif" font-size="11" text-rendering="geometricPrecision">
    <text x="{shield_x}" y="{baseline}" font-size="12">&#128737;</text>
    <text x="{label_x}" y="{baseline}" fill="#E5E7EB" font-weight="600">{label}</text>
    <text x="{value_cx}" y="{baseline}" fill="{fg}" font-weight="700" text-anchor="middle">{value}</text>
  </g>
</svg>'''
    return svg
