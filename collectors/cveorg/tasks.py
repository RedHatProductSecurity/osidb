from celery.schedules import crontab
from celery.utils.log import get_task_logger

from collectors.cveorg.collectors import CVEorgCollector
from collectors.cveorg.constants import CVEORG_COLLECTOR_ENABLED
from collectors.framework.models import collector

logger = get_task_logger(__name__)


@collector(
    base=CVEorgCollector,
    crontab=crontab(minute=0, hour="*/1"),  # Run every hour
    enabled=CVEORG_COLLECTOR_ENABLED,
)
def cveorg_collector(collector_obj) -> str:
    logger.info(f"Collector {collector_obj.name} is running")
    msg = collector_obj.collect()
    return msg
