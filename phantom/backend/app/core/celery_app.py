import os
from celery import Celery
from app.core.config import settings

CELERY_AVAILABLE = False

try:
    celery_app = Celery(
        "phantom_worker",
        broker=settings.redis_url,
        backend=settings.redis_url
    )

    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_soft_time_limit=600,
        task_time_limit=900,
        result_expires=3600,
        worker_pool="solo",
        imports=("app.tasks.scanner_tasks",),
    )
    CELERY_AVAILABLE = True
except Exception:
    celery_app = None
