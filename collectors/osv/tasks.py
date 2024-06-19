from celery.schedules import crontab
from celery.utils.log import get_task_logger

from collectors.framework.models import collector

from .collectors import OSVCollector
from .constants import OSV_COLLECTOR_ENABLED

logger = get_task_logger(__name__)


@collector(
    base=OSVCollector,
    crontab=crontab(minute=0, hour="*/1"),  # Run every hour
    depends_on=["collectors.bzimport.tasks.flaw_collector"],
    enabled=OSV_COLLECTOR_ENABLED,
)
def osv_collector(collector_obj) -> str:
    logger.info(f"Collector {collector_obj.name} is running")
    msg = collector_obj.collect()
    return msg
