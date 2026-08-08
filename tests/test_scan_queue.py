"""
Tests for the scan queue.

The whole point of the queue design is that the core logic runs without Celery
or Redis. These tests exercise request_scan and run_scan_job with a stub scan
function and a real (temp-file) store — proving the full flow end to end.

Run: pytest tests/test_scan_queue.py -v
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.scan_store import ScanStore
from core.scan_queue import request_scan, run_scan_job
from core.scanner import ScanOutcome


@pytest.fixture
def store(tmp_path):
    return ScanStore(db_path=tmp_path / "q.db")


def _stub_outcome(domain, grade="B", score=82.0):
    return ScanOutcome(
        domain=domain, grade=grade, score=score,
        scan_id=f"stub-{domain}", scanned_at=datetime.now(timezone.utc),
        attack_paths=0, raw_summary={},
    )


# ── request_scan ─────────────────────────────────────────────────────────────

def test_request_scan_queues_new_domain(store):
    enqueued = []
    status = request_scan("example.com", store, enqueued.append)
    assert status == "queued"
    assert enqueued == ["example.com"]
    assert store.is_pending("example.com")


def test_request_scan_dedupes_pending(store):
    enqueued = []
    request_scan("example.com", store, enqueued.append)   # queued
    status = request_scan("example.com", store, enqueued.append)  # again
    assert status == "pending"
    # Only enqueued ONCE despite two requests.
    assert enqueued == ["example.com"]


def test_request_scan_blocks_unsafe_target(store):
    enqueued = []
    status = request_scan("http://169.254.169.254", store, enqueued.append)
    assert status == "blocked"
    assert enqueued == []          # never enqueued


def test_request_scan_respects_cooldown(store):
    enqueued = []
    # A very recent grade exists → within cooldown → no new scan.
    store.seed("example.com", "A", 95.0, scanned_at=datetime.now(timezone.utc))
    status = request_scan("example.com", store, enqueued.append)
    assert status == "fresh"
    assert enqueued == []


def test_request_scan_requeues_after_cooldown(store):
    enqueued = []
    old = datetime.now(timezone.utc) - (store.RESCAN_COOLDOWN + timedelta(hours=1))
    store.seed("example.com", "A", 95.0, scanned_at=old)
    status = request_scan("example.com", store, enqueued.append)
    assert status == "queued"
    assert enqueued == ["example.com"]


# ── run_scan_job ─────────────────────────────────────────────────────────────

def test_run_scan_job_success_writes_grade(store):
    store.mark_queued("example.com")
    result = run_scan_job("example.com", store,
                          lambda d: _stub_outcome(d, "C", 72.7))
    assert result == "done"
    rec = store.get_grade("example.com")
    assert rec is not None
    assert rec.grade == "C"
    assert rec.score == 72.7
    assert rec.source == "scan"          # written via save_outcome, not seed
    assert store.job_status("example.com") == "done"


def test_run_scan_job_blocks_unsafe_at_execution(store):
    # Even if somehow enqueued, execution re-checks the guard.
    result = run_scan_job("http://127.0.0.1", store,
                          lambda d: _stub_outcome(d))
    assert result == "error"


def test_run_scan_job_handles_scan_failure(store):
    store.mark_queued("example.com")

    def boom(domain):
        raise RuntimeError("scan exploded")

    result = run_scan_job("example.com", store, boom)
    assert result == "error"
    assert store.job_status("example.com") == "error"
    # No grade should have been written.
    assert store.get_grade("example.com") is None


def test_full_flow_pending_then_done(store):
    """Simulate the real sequence: request → (worker) run → grade available."""
    enqueued = []

    # 1. First badge request — nothing stored, scan gets queued.
    status = request_scan("example.com", store, enqueued.append)
    assert status == "queued"
    assert store.get_grade("example.com") is None      # badge would show pending
    assert store.is_pending("example.com")

    # 2. Worker runs the job.
    run_scan_job("example.com", store, lambda d: _stub_outcome(d, "B", 82.0))

    # 3. Next badge request — real grade now available.
    rec = store.get_grade("example.com")
    assert rec.grade == "B"
    assert not store.is_pending("example.com")
