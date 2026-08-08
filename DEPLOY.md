# Deployment Guide

How to run the StackSentry platform with background scanning on the VPS.

## Components

The platform has three moving parts in production:

1. **Web app** (`app.py`) — serves badges, enqueues scans. Runs under Gunicorn.
2. **Redis** — the message broker between the web app and the worker.
3. **Celery worker** (`worker.py`) — runs scans out of band, writes grades.

A badge request never blocks on a scan: the web app returns a `pending` badge
instantly and the worker does the scanning separately.

## One-time setup

```bash
# On the VPS, in the platform directory:
python3 -m venv venv
source venv/bin/activate

# Install the platform's dependencies AND the real StackSentry engine:
pip install -r requirements.txt
# (requirements.txt already lists stacksentry>=1.0.0)

# Install and start Redis:
sudo apt-get install -y redis-server
sudo systemctl enable --now redis-server
```

## Running

Three processes. Use systemd units (below) or a process manager.

```bash
# 1. Redis (already running as a service after the setup above)

# 2. The Celery worker — runs the actual StackSentry scans:
celery -A worker.celery_app worker --loglevel=info

# 3. The web app under Gunicorn:
gunicorn -w 4 -b 127.0.0.1:5000 'app:app'
```

Then point nginx at `127.0.0.1:5000` for `badge.vickkykruzprogramming.dev`.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `STACKSENTRY_REDIS_URL` | `redis://localhost:6379/0` | Celery broker + result backend |

## systemd units (recommended)

`/etc/systemd/system/stacksentry-web.service`:

```ini
[Unit]
Description=StackSentry Platform Web
After=network.target redis-server.service

[Service]
WorkingDirectory=/opt/stacksentry-platform
ExecStart=/opt/stacksentry-platform/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/stacksentry-worker.service`:

```ini
[Unit]
Description=StackSentry Platform Scan Worker
After=network.target redis-server.service

[Service]
WorkingDirectory=/opt/stacksentry-platform
ExecStart=/opt/stacksentry-platform/venv/bin/celery -A worker.celery_app worker --loglevel=info
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now stacksentry-web stacksentry-worker
```

## How scanning behaves

- First badge request for a new domain → scan queued, badge shows `pending`
  (cached only 15s so it refreshes quickly).
- Worker runs the StackSentry quick scan, writes the grade.
- Next badge request → real grade, cached normally.
- A domain already queued/running is never re-queued (deduplication).
- A domain scanned within the last 6 hours is not re-scanned (cooldown).
- Any target that fails the SSRF guard is never queued or scanned.

## Safety

Every scan target passes the SSRF guard twice — once when the badge route
requests the scan, once inside the worker before scanning (DNS can change
between the two). Private, loopback, link-local, and cloud-metadata addresses
are refused. See `core/ssrf_guard.py`.
