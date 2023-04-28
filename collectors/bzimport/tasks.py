"""
Bugzilla collector celery tasks
"""
from celery.schedules import crontab
from celery.utils.log import get_task_logger

from collectors.framework.models import collector

from .collectors import BugzillaTrackerCollector, FlawCollector, MetadataCollector

logger = get_task_logger(__name__)


@collector(
    base=FlawCollector,
    crontab=crontab(),
    depends_on=["collectors.product_definitions.tasks.product_definitions_collector"],
)
def flaw_collector(collector_obj):
    """bugzilla flaw collector"""
    logger.info(f"Collector {collector_obj.name} is running")
    return collector_obj.collect()


@collector(
    base=BugzillaTrackerCollector,
    crontab=crontab(),
    depends_on=["collectors.bzimport.tasks.flaw_collector"],
)
def bztracker_collector(collector_obj):
    logger.info(f"Collector {collector_obj.name} is running")
    return collector_obj.collect()


@collector(
    base=MetadataCollector,
    # run once a day at 3:03
    crontab=crontab(hour=3, minute=3),
    depends_on=["collectors.product_definitions.tasks.product_definitions_collector"],
)
def metadata_collector(collector_obj):
    """
    Bugzilla metadata collector
    """
    logger.info(f"Collector {collector_obj.name} is running")
    return collector_obj.collect()
