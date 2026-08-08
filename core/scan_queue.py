"""
Scan Queue
==========

Runs scans OUT OF BAND so a badge request never blocks on one.

The flow:
  1. A badge is requested for a domain with no fresh grade.
  2. The route calls `request_scan(domain)` — which enqueues a job and returns
     immediately. The badge shows "pending".
  3. A Celery worker runs `run_scan_job(domain)` in the background: it scans
     with the real StackSentry scanner and writes the grade to the store.
  4. The next badge request reads the fresh grade.

Design; two layers on purpose
------------------------------
- `run_scan_job(domain, store, scan_fn)` is PLAIN PYTHON. It contains all the
  logic — guard, dedupe marks, scan, save — and takes the scan function as a
  parameter. This means the entire flow is unit-testable here with a stub
  scan_fn, no Celery and no Redis required.
- The Celery task `scan_task` is a thin wrapper that calls `run_scan_job` with
  the REAL scanner. On the VPS this is what actually runs in a worker process.

So the queue does not care whether the scan is real or stubbed — exactly what
lets us build and prove it here, then flip to real on the server unchanged.
"""

from __future__ import annotations
import os
from typing import Callable

from core.scan_store import ScanStore
from core.ssrf_guard import check_target


# ── Core job logic (plain Python, fully testable) ────────────────────────────

def request_scan(domain: str, store: ScanStore, enqueue: Callable[[str], None]) -> str:
    """
    Ask for a scan of `domain`. Returns one of:
      "queued"   — a new job was enqueued
      "pending"  — a job was already in flight (deduplicated)
      "fresh"    — a recent grade exists; no scan needed (cooldown)
      "blocked"  — the target failed the SSRF guard; never enqueued

    `enqueue` is the function that actually pushes the job to the worker
    (Celery in production, a direct call in tests).
    """
    # SSRF guard FIRST — an unsafe target must never be queued or scanned.
    guard = check_target(domain)
    if not guard.allowed:
        return "blocked"

    # mark_queued returns False if already pending or within cooldown.
    should_enqueue = store.mark_queued(domain)
    if not should_enqueue:
        # Distinguish "already running" from "recently scanned" for the caller.
        if store.is_pending(domain):
            return "pending"
        return "fresh"

    enqueue(domain)
    return "queued"


def run_scan_job(domain: str, store: ScanStore,
                 scan_fn: Callable[[str], object]) -> str:
    """
    Execute a scan job. This is what the worker runs.

    `scan_fn` takes a domain and returns a ScanOutcome (the real scanner in
    production, a stub in tests). Returns the final job status string.

    All exceptions are caught and recorded — a worker must never crash the
    queue on a single bad target.
    """
    # Re-check the guard at execution time too (defence in depth; DNS can change
    # between enqueue and run).
    guard = check_target(domain)
    if not guard.allowed:
        store.mark_error(domain, f"blocked: {guard.reason}")
        return "error"

    store.mark_running(domain)
    try:
        outcome = scan_fn(domain)
        store.save_outcome(outcome)
        store.mark_done(domain)
        return "done"
    except Exception as exc:
        store.mark_error(domain, str(exc))
        return "error"


# ── Celery wrapper (real worker on the VPS) ──────────────────────────────────
# Celery/Redis are only needed on the server. We construct the app lazily so
# importing this module never requires a running broker (e.g. in tests or CI).

_REDIS_URL = os.environ.get("STACKSENTRY_REDIS_URL", "redis://localhost:6379/0")

_celery_app = None


def get_celery():
    """Lazily construct the Celery app, so imports don't require a broker."""
    global _celery_app
    if _celery_app is None:
        from celery import Celery
        _celery_app = Celery("stacksentry", broker=_REDIS_URL, backend=_REDIS_URL)
        _celery_app.conf.update(
            task_serializer="json",
            accept_content=["json"],
            result_serializer="json",
            timezone="UTC",
            enable_utc=True,
            task_time_limit=120,          # a scan should never take 2 minutes
            task_soft_time_limit=90,
            worker_prefetch_multiplier=1, # fair dispatch across workers
        )
        _register_task(_celery_app)
    return _celery_app


def _register_task(celery_app):
    @celery_app.task(name="stacksentry.scan_task", bind=True, max_retries=2)
    def scan_task(self, domain: str):
        # Import the real scanner and a store here, inside the task, so the
        # worker process wires to real StackSentry at run time.
        from core.scanner import scan_domain
        store = ScanStore()
        return run_scan_job(domain, store, lambda d: scan_domain(d, mode="quick"))

    celery_app.scan_task = scan_task
    return scan_task


def enqueue_celery(domain: str) -> None:
    """Push a scan job to the Celery worker (production enqueue function)."""
    celery_app = get_celery()
    celery_app.scan_task.delay(domain)
