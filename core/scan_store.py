"""
StackSentry Scan Store
======================
 
Phase 2 (this file): the READ path only.
 
A small SQLite-backed store mapping a verified domain to its latest security
grade. The badge endpoint reads from this store instead of from a query
parameter.
 
Deliberate design decision — NO WRITE ENDPOINT YET
--------------------------------------------------
This module exposes `get_grade()` (read) and a `seed()` helper for tests and
local development. It does NOT expose an HTTP write path. Publishing a grade
must go through server-side scanning + domain verification, which is the next
build. Until that exists, the only way data enters the store is via `seed()`,
which is not reachable over the network.
 
This keeps us honest: at no point does the service accept an unauthenticated
"here is my grade" write. On a security product, an open write endpoint —
even a temporary one — would undermine the whole trust model.
 
Schema
------
grades(
    domain        TEXT PRIMARY KEY,   -- normalised, e.g. "example.com"
    grade         TEXT,               -- "A".."F"
    score         REAL,               -- 0..100
    scanned_at    TEXT,               -- ISO 8601 UTC
    scan_id       TEXT,               -- opaque id linking to the full scan
    source        TEXT                -- how it got here: "seed" | "scan"
)
"""
 
from __future__ import annotations
import sqlite3
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dataclasses import dataclass
 
# Grades older than this are considered stale and the badge shows "stale"
# rather than a potentially misleading old grade.
STALE_AFTER = timedelta(days=30)
 
DEFAULT_DB_PATH = Path.home() / ".stacksentry" / "badge_store.db"
 
_VALID_GRADES = {"A", "B", "C", "D", "F"}
 
 
@dataclass
class GradeRecord:
    domain: str
    grade: str
    score: float
    scanned_at: datetime
    scan_id: str
    source: str
 
    @property
    def is_stale(self) -> bool:
        age = datetime.now(timezone.utc) - self.scanned_at
        return age > STALE_AFTER
 
    @property
    def age_days(self) -> int:
        return (datetime.now(timezone.utc) - self.scanned_at).days
 
 
@dataclass
class VerificationRecord:
    """A domain-ownership verification record."""
    domain: str
    token: str
    verified: bool
    method: str | None
    issued_at: datetime
    verified_at: datetime | None
 
 
# ── Domain normalisation ─────────────────────────────────────────────────────
# We store one canonical form per domain so "Example.com", "example.com/", and
# "https://example.com" all map to the same row.
 
_SCHEME_RE = re.compile(r"^[a-z]+://", re.I)
 
 
def normalise_domain(raw: str) -> str | None:
    """
    Reduce a user-supplied domain/URL to a canonical bare host.
 
    Returns None if the input does not look like a valid host — this matters
    because the value flows in from a URL path and must not be trusted blindly.
    """
    if not raw:
        return None
    d = raw.strip().lower()
    d = _SCHEME_RE.sub("", d)          # strip scheme
    d = d.split("/", 1)[0]             # strip path
    d = d.split("?", 1)[0]             # strip query
    d = d.split("#", 1)[0]             # strip fragment
    d = d.split(":", 1)[0]             # strip port
    d = d.strip(".")                   # strip stray dots
    # A valid host: labels of alnum/hyphen separated by dots, at least one dot.
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", d):
        return None
    return d
 
 
# ── Store ────────────────────────────────────────────────────────────────────
 
class ScanStore:
    """Read access to the badge grade store. No public write path."""
 
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
 
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn
 
    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS grades (
                    domain     TEXT PRIMARY KEY,
                    grade      TEXT NOT NULL,
                    score      REAL NOT NULL,
                    scanned_at TEXT NOT NULL,
                    scan_id    TEXT NOT NULL,
                    source     TEXT NOT NULL DEFAULT 'scan'
                )
            """)
            # Tracks in-flight and recent scan jobs, so we can:
            #   - show a "pending" badge while a first scan runs
            #   - deduplicate: never queue a domain that is already queued
            #   - rate-limit: never re-queue a domain scanned very recently
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    domain       TEXT PRIMARY KEY,
                    status       TEXT NOT NULL,   -- queued | running | done | error
                    requested_at TEXT NOT NULL,   -- ISO 8601 UTC
                    updated_at   TEXT NOT NULL,   -- ISO 8601 UTC
                    detail       TEXT             -- error message, if any
                )
            """)
            # Records domain-ownership verification, separate from grades because
            # a grade (what the scan found) and a verification (who may publish
            # it) are different facts with different lifecycles. A domain may have
            # a grade with no verification, or a verification that expires while
            # the grade stays valid.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS domain_verifications (
                    domain      TEXT PRIMARY KEY,
                    token       TEXT NOT NULL,   -- the issued verification token
                    verified    INTEGER NOT NULL DEFAULT 0,  -- 0/1
                    method      TEXT,            -- dns | well_known | NULL
                    issued_at   TEXT NOT NULL,   -- ISO 8601 UTC
                    verified_at TEXT             -- ISO 8601 UTC, NULL until verified
                )
            """)
 
    # ── Read path (public) ──────────────────────────────────────────────────
 
    def get_grade(self, domain: str) -> GradeRecord | None:
        """
        Return the stored GradeRecord for a domain, or None if not found.
 
        The domain is normalised first; an invalid domain returns None rather
        than raising, so the badge endpoint can fall back to an "unknown" badge.
        """
        norm = normalise_domain(domain)
        if norm is None:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM grades WHERE domain = ?", (norm,)
            ).fetchone()
        if row is None:
            return None
        return GradeRecord(
            domain=row["domain"],
            grade=row["grade"],
            score=row["score"],
            scanned_at=datetime.fromisoformat(row["scanned_at"]),
            scan_id=row["scan_id"],
            source=row["source"],
        )
 
    # ── Scan job tracking (pending state + deduplication) ────────────────────
 
    # Do not re-queue a domain scanned more recently than this. Blunts abuse
    # (refresh spam can't trigger endless scans) and avoids redundant work.
    RESCAN_COOLDOWN = timedelta(hours=6)
 
    def job_status(self, domain: str) -> str | None:
        """Return the current job status for a domain, or None if no job exists."""
        norm = normalise_domain(domain)
        if norm is None:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM scan_jobs WHERE domain = ?", (norm,)
            ).fetchone()
        return row["status"] if row else None
 
    def is_pending(self, domain: str) -> bool:
        """True if a scan for this domain is queued or running."""
        return self.job_status(domain) in ("queued", "running")
 
    def mark_queued(self, domain: str) -> bool:
        """
        Mark a domain as queued for scanning.
 
        Returns True if the caller should actually enqueue a job, False if the
        domain is already queued/running or was scanned within the cooldown
        window (deduplication + rate control). This is the single gate that
        prevents a popular badge from spawning endless duplicate scans.
        """
        norm = normalise_domain(domain)
        if norm is None:
            return False
 
        now = datetime.now(timezone.utc)
 
        # Already in flight? Do not enqueue again.
        if self.is_pending(norm):
            return False
 
        # Scanned very recently? Respect the cooldown.
        existing = self.get_grade(norm)
        if existing is not None:
            age = now - existing.scanned_at
            if age < self.RESCAN_COOLDOWN:
                return False
 
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scan_jobs "
                "(domain, status, requested_at, updated_at, detail) "
                "VALUES (?, 'queued', ?, ?, NULL)",
                (norm, now.isoformat(), now.isoformat()),
            )
        return True
 
    def mark_running(self, domain: str) -> None:
        self._update_job(domain, "running")
 
    def mark_done(self, domain: str) -> None:
        self._update_job(domain, "done")
 
    def mark_error(self, domain: str, detail: str) -> None:
        self._update_job(domain, "error", detail=detail)
 
    def _update_job(self, domain: str, status: str, detail: str | None = None) -> None:
        norm = normalise_domain(domain)
        if norm is None:
            return
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE scan_jobs SET status = ?, updated_at = ?, detail = ? "
                "WHERE domain = ?",
                (status, now, detail, norm),
            )
 
    # ── Write path used by the scan worker ───────────────────────────────────
 
    def save_outcome(self, outcome) -> GradeRecord:
        """
        Persist a scan result produced by the platform's own scanner.
 
        This is the ONLY write path for real grades, and it is called by the
        background worker AFTER a server-side scan — never by an HTTP request
        carrying a client-supplied grade. `outcome` is a ScanOutcome from
        core.scanner (duck-typed here to avoid a circular import).
        """
        return self.seed(
            outcome.domain,
            outcome.grade,
            outcome.score,
            scan_id=outcome.scan_id,
            scanned_at=outcome.scanned_at,
            source="scan",
        )
 
    # ── Seed helper (local/testing only — NOT an HTTP endpoint) ──────────────
 
    def seed(self, domain: str, grade: str, score: float,
             *, scan_id: str = "seed", scanned_at: datetime | None = None,
             source: str = "seed") -> GradeRecord:
        """
        Insert or replace a grade directly. This is for local development and
        tests only. It is intentionally a Python method, not reachable over
        HTTP, so it cannot be used to publish a fake grade remotely.
        """
        norm = normalise_domain(domain)
        if norm is None:
            raise ValueError(f"Invalid domain: {domain!r}")
        g = grade.upper().strip()
        if g not in _VALID_GRADES:
            raise ValueError(f"Invalid grade: {grade!r}")
        if not (0 <= score <= 100):
            raise ValueError(f"Score out of range: {score!r}")
        ts = scanned_at or datetime.now(timezone.utc)
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO grades "
                "(domain, grade, score, scanned_at, scan_id, source) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (norm, g, score, ts.isoformat(), scan_id, source),
            )
        return GradeRecord(norm, g, score, ts, scan_id, source)
 
    # ── Domain verification records ──────────────────────────────────────────
 
    def save_verification_token(self, domain: str, token: str,
                                issued_at: datetime | None = None) -> None:
        """
        Store (or replace) an issued verification token for a domain. This marks
        the domain as NOT yet verified — verification happens later when the
        owner publishes the token and we confirm it.
        """
        norm = normalise_domain(domain)
        if norm is None:
            raise ValueError(f"invalid domain: {domain!r}")
        ts = (issued_at or datetime.now(timezone.utc)).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO domain_verifications "
                "(domain, token, verified, method, issued_at, verified_at) "
                "VALUES (?, ?, 0, NULL, ?, NULL)",
                (norm, token, ts),
            )
 
    def mark_verified(self, domain: str, method: str,
                      verified_at: datetime | None = None) -> None:
        """
        Mark a domain as verified by a given method. Requires a token to have
        been issued first (the row must exist); we never create a verified row
        out of thin air.
        """
        norm = normalise_domain(domain)
        if norm is None:
            raise ValueError(f"invalid domain: {domain!r}")
        ts = (verified_at or datetime.now(timezone.utc)).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE domain_verifications "
                "SET verified = 1, method = ?, verified_at = ? WHERE domain = ?",
                (method, ts, norm),
            )
            if cur.rowcount == 0:
                raise ValueError(
                    f"no verification token issued for {norm!r}; "
                    "call save_verification_token first"
                )
 
    def get_verification(self, domain: str) -> VerificationRecord | None:
        """Return the VerificationRecord for a domain, or None if none exists."""
        norm = normalise_domain(domain)
        if norm is None:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM domain_verifications WHERE domain = ?", (norm,)
            ).fetchone()
        if row is None:
            return None
        return VerificationRecord(
            domain=row["domain"],
            token=row["token"],
            verified=bool(row["verified"]),
            method=row["method"],
            issued_at=datetime.fromisoformat(row["issued_at"]),
            verified_at=datetime.fromisoformat(row["verified_at"])
            if row["verified_at"] else None,
        )
 
    def is_domain_verified(self, domain: str,
                           ttl: timedelta = None) -> bool:
        """
        True only if the domain has a verification that is both marked verified
        AND still within its TTL. This is the single check the badge-publishing
        path uses: no current verification → no public grade.
 
        `ttl` defaults to the verification TTL (90 days). A domain verified
        longer ago than the TTL is treated as unverified until re-confirmed.
        """
        rec = self.get_verification(domain)
        if rec is None or not rec.verified or rec.verified_at is None:
            return False
        window = ttl if ttl is not None else timedelta(days=90)
        verified_at = rec.verified_at
        if verified_at.tzinfo is None:
            verified_at = verified_at.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - verified_at) < window
 
    def count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM grades").fetchone()[0]
 