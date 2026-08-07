"""
Tests for the StackSentry hex-seal badge renderer.

Run: pytest test_seal_badge.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


import re
import pytest
from features.badges.seal_badge import render_seal_badge, GRADE_COLOURS, STATE_COLOURS


# ── Valid SVG structure ──────────────────────────────────────────────────────

@pytest.mark.parametrize("grade", ["A", "B", "C", "D", "F"])
def test_seal_is_valid_svg(grade):
    svg = render_seal_badge(grade, score=80)
    assert svg.startswith("<svg")
    assert svg.strip().endswith("</svg>")
    assert 'xmlns="http://www.w3.org/2000/svg"' in svg


# ── The hexagon seal is always present ───────────────────────────────────────

def test_hexagon_path_present():
    svg = render_seal_badge("B", score=82)
    # The flat-top hexagon has 6 vertices — its path starts with M and has 5 L segments.
    hex_paths = [line for line in svg.split("<path") if "Z" in line and line.count(" L") >= 4]
    assert len(hex_paths) >= 1


def test_shield_glyph_present():
    svg = render_seal_badge("A", score=95)
    # The seal contains a shield + checkmark drawn in teal.
    assert "#10B981" in svg


# ── Correct grade colour ─────────────────────────────────────────────────────

@pytest.mark.parametrize("grade,expected_bg", [
    ("A", "#16A34A"),
    ("B", "#2563EB"),
    ("C", "#0E7490"),
    ("D", "#D97706"),
    ("F", "#DC2626"),
])
def test_grade_colour(grade, expected_bg):
    svg = render_seal_badge(grade, score=80)
    assert expected_bg in svg


# ── Grade letter present ─────────────────────────────────────────────────────

@pytest.mark.parametrize("grade", ["A", "B", "C", "D", "F"])
def test_grade_letter_present(grade):
    svg = render_seal_badge(grade)
    assert f">{grade}</text>" in svg


# ── Live pulse control ───────────────────────────────────────────────────────

def test_live_dot_present_by_default():
    svg = render_seal_badge("B", score=82)
    assert "<animate" in svg


def test_live_dot_removed_when_disabled():
    svg = render_seal_badge("B", score=82, live=False)
    assert "<animate" not in svg


# ── State handling ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("state", ["unknown", "stale", "error", "unverified"])
def test_state_overrides_grade(state):
    svg = render_seal_badge("A", score=95, state=state)
    assert state in svg
    # Grade A green must NOT be used when a state overrides it.
    assert GRADE_COLOURS["A"]["bg"] not in svg


# ── Verified label ───────────────────────────────────────────────────────────

def test_verified_label_on_valid_grade():
    svg = render_seal_badge("B", score=82)
    assert "verified" in svg


def test_unknown_label_on_invalid_grade():
    svg = render_seal_badge("Z")
    assert "unknown" in svg


# ── Safety ───────────────────────────────────────────────────────────────────

def test_grade_input_escaped():
    svg = render_seal_badge("<script>")
    assert "<script>" not in svg


def test_lowercase_normalised():
    svg = render_seal_badge("c", score=73)
    assert GRADE_COLOURS["C"]["bg"] in svg


# ── Dimensions are sensible ──────────────────────────────────────────────────

def test_badge_height_is_30():
    svg = render_seal_badge("A", score=95)
    h = int(re.search(r'height="(\d+)"', svg).group(1))
    assert h == 30


def test_badge_has_positive_width():
    svg = render_seal_badge("A", score=95)
    w = int(re.search(r'width="(\d+)"', svg).group(1))
    assert w > 100
