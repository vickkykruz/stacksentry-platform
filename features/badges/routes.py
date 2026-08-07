"""
Badges feature — HTTP routes.

Serves the security-grade SVG badge for a domain. The grade is read from the
shared scan store (populated by server-side StackSentry scans). This module
owns only the badge-serving concern; scanning, storage, and the SSRF guard
live in core/.

Grade resolution order for /grade/<domain>.svg:
  1. ?grade= override (development/preview only)
  2. store lookup for the domain
  3. stale (>30 days) → "stale" badge
  4. not found → "unknown" badge
"""

from __future__ import annotations
from flask import Blueprint, Response, request, render_template_string

from features.badges.badge_render import render_badge, render_flat_badge, GRADE_COLOURS
from features.badges.seal_badge import render_seal_badge

badges_bp = Blueprint("badges", __name__)

# The store is injected by init_badges() at app startup so this feature does
# not create its own store instance — the whole platform shares one.
_store = None
_CACHE_SECONDS = 60


def init_badges(store):
    """Inject the shared scan store into this feature."""
    global _store
    _store = store


def _svg_response(svg: str) -> Response:
    resp = Response(svg, mimetype="image/svg+xml")
    resp.headers["Cache-Control"] = f"max-age={_CACHE_SECONDS}, public"
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@badges_bp.route("/grade/<path:domain>.svg")
def grade_badge(domain: str):
    style = request.args.get("style", "seal")
    live = request.args.get("live", "1") != "0"

    grade = ""
    score = None
    state = request.args.get("state")

    override = request.args.get("grade")
    if override is not None:
        # Dev/preview path only.
        grade = override
        score_raw = request.args.get("score")
        if score_raw is not None:
            try:
                score = float(score_raw)
            except ValueError:
                score = None
    elif state is None:
        # Production path — grade comes from the store.
        record = _store.get_grade(domain) if _store else None
        if record is None:
            state = "unknown"
        elif record.is_stale:
            state = "stale"
        else:
            grade = record.grade
            score = record.score

    if style == "classic":
        svg = render_badge(grade, score=score, state=state)
    elif style == "flat":
        svg = render_flat_badge(grade, score=score, state=state)
    else:
        svg = render_seal_badge(grade, score=score, state=state, live=live)

    return _svg_response(svg)


@badges_bp.route("/badges/preview")
def preview():
    grades = list(GRADE_COLOURS.keys())
    return render_template_string(_PREVIEW_HTML, grades=grades)


_PREVIEW_HTML = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>StackSentry Badge Preview</title>
<style>
  body { background:#0d1b2a; color:#e5e7eb; font-family:Inter,Segoe UI,sans-serif; margin:0; padding:3rem; }
  h1 { color:#10b981; } h2 { color:#93c5fd; font-size:.9rem; text-transform:uppercase;
       letter-spacing:.1em; margin-top:2.5rem; border-bottom:1px solid #1e293b; padding-bottom:.5rem; }
  .row { display:flex; align-items:center; gap:1.5rem; margin:1rem 0; }
  .row img { height:30px; } .lbl { color:#6b7280; font-size:.8rem; width:9rem; }
</style></head><body>
  <h1>🛡 StackSentry Badge Preview</h1>
  <h2>Seal style (signature)</h2>
  {% for g in grades %}
  <div class="row">
    <span class="lbl">Grade {{ g }}</span>
    <img src="/grade/example.com.svg?grade={{ g }}&score={{ {'A':95,'B':82,'C':73,'D':64,'F':27}[g] }}" alt="grade {{ g }}">
  </div>
  {% endfor %}
  <div class="row"><span class="lbl">Unknown</span><img src="/grade/x.svg?state=unknown"></div>
  <div class="row"><span class="lbl">Stale</span><img src="/grade/x.svg?state=stale"></div>
</body></html>
"""
