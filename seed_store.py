"""
Seed the badge store with sample grades for local development.

This is a LOCAL utility. It calls ScanStore.seed() directly — there is no
network write path. Run it once to populate the store so the badge endpoint
has real data to read (instead of relying on ?grade= overrides).

Usage:
    python seed_store.py
"""

from datetime import datetime, timezone, timedelta
from scan_store import ScanStore


SAMPLES = [
    # domain,                          grade, score, age_days
    ("admin.vickkykruzprogramming.dev", "C", 72.7, 0),
    ("bblearn.londonmet.ac.uk",         "D", 66.7, 2),
    ("sacoeteccscdept.com.ng",          "F", 27.3, 5),
    ("example.com",                     "A", 95.0, 1),
    ("staging.example.com",             "B", 82.0, 10),
    # An intentionally stale one (>30 days) to test the "stale" badge state.
    ("old-project.dev",                 "A", 91.0, 45),
]


def main():
    store = ScanStore()
    now = datetime.now(timezone.utc)
    for domain, grade, score, age in SAMPLES:
        scanned_at = now - timedelta(days=age)
        rec = store.seed(domain, grade, score,
                         scan_id=f"seed-{domain}",
                         scanned_at=scanned_at)
        flag = "  (STALE)" if rec.is_stale else ""
        print(f"  seeded {domain:<38} {grade} {score:>5.1f}%  {age}d ago{flag}")
    print(f"\nStore now holds {store.count()} grades.")


if __name__ == "__main__":
    main()
