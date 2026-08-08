"""
Celery worker entry point.

Run the background scan worker on the VPS with:

    # 1. Make sure Redis is running (the broker):
    redis-server

    # 2. Make sure StackSentry is installed in the same environment:
    pip install stacksentry

    # 3. Start the worker:
    celery -A worker.celery_app worker --loglevel=info

The web app (app.py) enqueues scan jobs; this worker executes them out of band
by calling the real StackSentry scanner and writing grades to the store.

Environment:
    STACKSENTRY_REDIS_URL   broker/result URL (default redis://localhost:6379/0)
"""

from core.scan_queue import get_celery

# `celery -A worker.celery_app worker` needs a module-level Celery instance.
celery_app = get_celery()
