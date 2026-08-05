from celery.schedules import crontab
from celery.utils.log import get_task_logger

from collectors.cveorg.collectors import CVEorgCollector
from collectors.cveorg.constants import CVEORG_COLLECTOR_ENABLED
from collectors.framework.models import collector

logger = get_task_logger(__name__)


@collector(
    base=CVEorgCollector,
    crontab=crontab(minute="*/10"),  # Run every 10 minutes
    enabled=CVEORG_COLLECTOR_ENABLED,
)
def cveorg_collector(collector_obj) -> str:
    logger.info(f"Collector {collector_obj.name} is running")
    msg = collector_obj.collect()
    return msg
