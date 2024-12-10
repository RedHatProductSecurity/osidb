"""
Celery tasks for the OSIDB Collector
"""

from celery.schedules import crontab
from celery.utils.log import get_task_logger

from collectors.framework.models import collector
from osidb.mixins import Alert

from .collectors import StaleAlertCollector

logger = get_task_logger(__name__)


@collector(
    base=StaleAlertCollector,
    crontab=crontab(minute=0, hour="*/1"),  # Run every hour
    data_models=[Alert],
)
def osidb_stale_alert_collector(collector_obj):
    logger.info(f"Collector {collector_obj.name} is running")
    return collector_obj.collect()
