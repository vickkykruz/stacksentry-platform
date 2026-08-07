"""
Tests for the StackSentry scan store.

Run: pytest test_scan_store.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


import pytest
from datetime import datetime, timezone, timedelta
from core.scan_store import ScanStore, normalise_domain, GradeRecord, STALE_AFTER


@pytest.fixture
def store(tmp_path):
    return ScanStore(db_path=tmp_path / "test_store.db")


# ── Domain normalisation ─────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("Example.COM", "example.com"),
    ("https://example.com", "example.com"),
    ("https://example.com/path/page", "example.com"),
    ("http://example.com:8080", "example.com"),
    ("example.com/", "example.com"),
    ("example.com?query=1", "example.com"),
    ("  example.com  ", "example.com"),
    ("sub.example.co.uk", "sub.example.co.uk"),
])
def test_normalise_valid(raw, expected):
    assert normalise_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "not a domain", "localhost", "just-text",
    "http://", "...", "example", "a b c",
])
def test_normalise_invalid_returns_none(raw):
    assert normalise_domain(raw) is None


# ── Seed and read ────────────────────────────────────────────────────────────

def test_seed_and_get(store):
    store.seed("example.com", "B", 82.0)
    rec = store.get_grade("example.com")
    assert rec is not None
    assert rec.grade == "B"
    assert rec.score == 82.0
    assert rec.domain == "example.com"


def test_get_normalises_lookup(store):
    store.seed("example.com", "A", 95.0)
    # Look up with a messy form — should still find it.
    rec = store.get_grade("https://Example.com/some/path")
    assert rec is not None
    assert rec.grade == "A"


def test_get_missing_returns_none(store):
    assert store.get_grade("never-seeded.com") is None


def test_get_invalid_domain_returns_none(store):
    assert store.get_grade("not a domain") is None


# ── Upsert behaviour ─────────────────────────────────────────────────────────

def test_seed_replaces_existing(store):
    store.seed("example.com", "F", 20.0)
    store.seed("example.com", "A", 95.0)
    rec = store.get_grade("example.com")
    assert rec.grade == "A"
    assert store.count() == 1        # replaced, not duplicated


# ── Staleness ────────────────────────────────────────────────────────────────

def test_fresh_grade_not_stale(store):
    store.seed("fresh.com", "A", 95.0)
    rec = store.get_grade("fresh.com")
    assert not rec.is_stale


def test_old_grade_is_stale(store):
    old = datetime.now(timezone.utc) - (STALE_AFTER + timedelta(days=1))
    store.seed("old.com", "A", 95.0, scanned_at=old)
    rec = store.get_grade("old.com")
    assert rec.is_stale


def test_age_days(store):
    ts = datetime.now(timezone.utc) - timedelta(days=7)
    store.seed("week.com", "B", 80.0, scanned_at=ts)
    rec = store.get_grade("week.com")
    assert rec.age_days == 7


# ── Validation on seed ───────────────────────────────────────────────────────

def test_seed_rejects_invalid_grade(store):
    with pytest.raises(ValueError):
        store.seed("example.com", "Z", 50.0)


def test_seed_rejects_bad_score(store):
    with pytest.raises(ValueError):
        store.seed("example.com", "A", 150.0)


def test_seed_rejects_invalid_domain(store):
    with pytest.raises(ValueError):
        store.seed("not a domain", "A", 95.0)


# ── Count ────────────────────────────────────────────────────────────────────

def test_count(store):
    assert store.count() == 0
    store.seed("a.com", "A", 95.0)
    store.seed("b.com", "B", 82.0)
    assert store.count() == 2
