"""
Celery tasks for the JIRA Collector
"""

from celery.schedules import crontab
from celery.utils.log import get_task_logger

from collectors.framework.models import collector
from osidb.models import Flaw, Tracker

from .collectors import JiraTaskCollector, JiraTrackerCollector, MetadataCollector
from .constants import (
    JIRA_METADATA_COLLECTOR_ENABLED,
    JIRA_TASK_COLLECTOR_ENABLED,
    JIRA_TRACKER_COLLECTOR_ENABLED,
)

logger = get_task_logger(__name__)


@collector(
    base=JiraTaskCollector,
    crontab=crontab(),  # run every minute
    data_models=[Flaw],
    enabled=JIRA_TASK_COLLECTOR_ENABLED,
)
def jira_task_collector(collector_obj):
    logger.info(f"Collector {collector_obj.name} is running")
    return collector_obj.collect()


@collector(
    base=JiraTrackerCollector,
    crontab=crontab(),  # run every minute
    data_models=[Tracker],
    depends_on=["collectors.product_definitions.tasks.product_definitions_collector"],
    enabled=JIRA_TRACKER_COLLECTOR_ENABLED,
)
def jira_tracker_collector(collector_obj):
    logger.info(f"Collector {collector_obj.name} is running")
    return collector_obj.collect()


@collector(
    base=MetadataCollector,
    crontab=crontab(minute="0", hour="*/3"),  # run every three hours
    depends_on=["collectors.product_definitions.tasks.product_definitions_collector"],
    enabled=JIRA_METADATA_COLLECTOR_ENABLED,
)
def metadata_collector(collector_obj):
    """
    Jira metadata collector
    """
    logger.info(f"Collector {collector_obj.name} is running")
    return collector_obj.collect()
