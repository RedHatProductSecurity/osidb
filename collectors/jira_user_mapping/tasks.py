"""
Jira user mapping collector task
"""

from celery.schedules import crontab
from celery.utils.log import get_task_logger
from django.utils import timezone

from collectors.framework.models import collector
from osidb.models.jira_user_mapping import JiraUserMapping

from .collectors import JiraUserMappingCollector
from .constants import jira_user_mapping_collector_settings

logger = get_task_logger(__name__)


@collector(
    base=JiraUserMappingCollector,
    crontab=crontab(minute=0, hour=3),
    data_models=[JiraUserMapping],
    enabled=jira_user_mapping_collector_settings.enabled,
)
def jira_user_mapping_collector(collector_obj) -> str:
    logger.info(f"Collector {collector_obj.name} is running")

    msg = collector_obj.collect()

    collector_obj.store(updated_until_dt=timezone.now())

    return msg
