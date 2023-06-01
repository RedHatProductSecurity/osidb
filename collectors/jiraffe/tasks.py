"""
Celery tasks for the JIRA Collector
"""
from celery.schedules import crontab
from celery.utils.log import get_task_logger

from collectors.framework.models import collector
from osidb.models import Tracker

from .collectors import JiraTrackerCollector, MetadataCollector

logger = get_task_logger(__name__)


@collector(
    base=JiraTrackerCollector,
    crontab=crontab(),  # run every minute
    data_models=[Tracker],
    depends_on=["collectors.bzimport.tasks.flaw_collector"],
)
def jira_tracker_collector(collector_obj):
    logger.info(f"Collector {collector_obj.name} is running")
    return collector_obj.collect()


@collector(
    base=MetadataCollector,
    # run once a day at 2:35
    crontab=crontab(hour=2, minute=35),
    depends_on=["collectors.product_definitions.tasks.product_definitions_collector"],
)
def metadata_collector(collector_obj):
    """
    Jira metadata collector
    """
    logger.info(f"Collector {collector_obj.name} is running")
    return collector_obj.collect()
