"""
Tests for the StackSentry badge renderer.

Run: pytest test_badge_render.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


import re
import pytest
from features.badges.badge_render import (
    render_flat_badge, render_badge,
    GRADE_COLOURS, STATE_COLOURS, LABEL_TEXT,
)


# ── Valid SVG structure ──────────────────────────────────────────────────────

@pytest.mark.parametrize("grade", ["A", "B", "C", "D", "F"])
def test_flat_badge_is_valid_svg(grade):
    svg = render_flat_badge(grade, score=80)
    assert svg.startswith("<svg")
    assert svg.strip().endswith("</svg>")
    assert 'xmlns="http://www.w3.org/2000/svg"' in svg


@pytest.mark.parametrize("grade", ["A", "B", "C", "D", "F"])
def test_classic_badge_is_valid_svg(grade):
    svg = render_badge(grade, score=80)
    assert svg.startswith("<svg")
    assert svg.strip().endswith("</svg>")


# ── Correct colour per grade ─────────────────────────────────────────────────

@pytest.mark.parametrize("grade,expected_bg", [
    ("A", "#16A34A"),
    ("B", "#2563EB"),
    ("C", "#0E7490"),
    ("D", "#D97706"),
    ("F", "#DC2626"),
])
def test_grade_colour_matches(grade, expected_bg):
    svg = render_flat_badge(grade, score=80)
    assert expected_bg in svg


# ── Grade letter appears in the badge ────────────────────────────────────────

@pytest.mark.parametrize("grade", ["A", "B", "C", "D", "F"])
def test_grade_letter_present(grade):
    svg = render_flat_badge(grade)
    # The grade letter should appear in the value text element.
    assert f">{grade}</text>" in svg or f"{grade} \u00b7" in svg


# ── Score formatting ─────────────────────────────────────────────────────────

def test_score_shown_when_provided():
    svg = render_flat_badge("B", score=82)
    assert "82%" in svg


def test_score_rounded():
    svg = render_flat_badge("C", score=72.7)
    assert "73%" in svg          # 72.7 rounds to 73
    assert "72.7" not in svg


def test_no_score_shows_letter_only():
    svg = render_flat_badge("A")
    assert "%" not in svg


# ── State overrides ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("state", ["unknown", "stale", "error", "unverified"])
def test_state_overrides_grade(state):
    svg = render_flat_badge("A", score=95, state=state)
    # Even though grade A was passed, the state text should win.
    assert state in svg
    # And the green A colour should NOT be used.
    assert GRADE_COLOURS["A"]["bg"] not in svg


# ── Unknown/invalid grade handling ───────────────────────────────────────────

def test_invalid_grade_shows_unknown():
    svg = render_flat_badge("Z")
    assert "unknown" in svg


def test_empty_grade_shows_unknown():
    svg = render_flat_badge("")
    assert "unknown" in svg


def test_lowercase_grade_normalised():
    svg = render_flat_badge("b", score=80)
    assert GRADE_COLOURS["B"]["bg"] in svg


# ── Label always present ─────────────────────────────────────────────────────

def test_label_present():
    svg = render_flat_badge("A")
    assert LABEL_TEXT in svg


# ── XSS / injection safety ───────────────────────────────────────────────────

def test_grade_input_is_escaped():
    # A malicious grade string must not break out of the SVG.
    svg = render_flat_badge("<script>alert(1)</script>")
    assert "<script>" not in svg
    # It should fall through to "unknown" since it is not a valid grade.
    assert "unknown" in svg


# ── Width scales with content ────────────────────────────────────────────────

def test_width_grows_with_score():
    narrow = render_flat_badge("A")
    wide = render_flat_badge("A", score=95)
    nw = int(re.search(r'width="(\d+)"', narrow).group(1))
    ww = int(re.search(r'width="(\d+)"', wide).group(1))
    assert ww > nw
