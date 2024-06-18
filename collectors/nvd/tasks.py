"""
NVD collector celery tasks
"""
from celery.schedules import crontab
from celery.utils.log import get_task_logger

from collectors.framework.models import collector

from .collectors import NVDCollector
from .constants import NVD_COLLECTOR_ENABLED

logger = get_task_logger(__name__)


@collector(
    base=NVDCollector,
    # run every ten minutes
    # this way the initial sync will take probably between half day
    # and one day as it proceeds by 100 days starting at 1999
    crontab=crontab(minute="*/10"),
    depends_on=["collectors.bzimport.tasks.flaw_collector"],
    enabled=NVD_COLLECTOR_ENABLED,
)
def nvd_collector(collector_obj) -> str:
    """NVD collector"""
    logger.info(f"Collector {collector_obj.name} is running")
    msg1 = collector_obj.collect_updated()
    msg2 = collector_obj.collect()
    return f"{msg1}\n{msg2}"
