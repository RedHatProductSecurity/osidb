"""
Celery tasks for the JIRA Collector
"""
from celery import shared_task
from celery.utils.log import get_task_logger
from django.conf import settings

from config.celery import app
from osidb.core import set_user_acls
from osidb.models import Affect

from .constants import (
    JIRA_MAX_TRIES,
    JIRA_RATE_LIMIT,
    JIRA_SOFT_TIME_LIMIT,
    JIRA_SYNC_INTERVAL,
    JIRAFFE_AUTO_SYNC,
)
from .core import get_affects_to_sync, upsert_trackers

logger = get_task_logger(__name__)


@app.task(
    max_retries=JIRA_MAX_TRIES,
    soft_time_limit=JIRA_SOFT_TIME_LIMIT,
    rate_limit=JIRA_RATE_LIMIT,
)
def process_affect(affect_uuid, groups_read, groups_write):
    """
    Fetches an affect and creates or updates any Trackers related to it
    """
    # Essentially bypass ACLs, celery workers should be able to read/write any
    # information in order to fulfill their jobs
    set_user_acls(
        settings.PUBLIC_READ_GROUPS
        + [
            settings.PUBLIC_WRITE_GROUP,
            settings.EMBARGO_READ_GROUP,
            settings.EMBARGO_WRITE_GROUP,
        ]
    )
    affect = Affect.objects.get(uuid=affect_uuid)
    upsert_trackers(affect)


@shared_task
def jiraffe_sync():
    """
    Regularly polls the JIRA API for updated trackers to update them internally
    """
    if JIRAFFE_AUTO_SYNC:
        affect_uuids = get_affects_to_sync(JIRA_SYNC_INTERVAL)
        if affect_uuids:
            for affect_uuid in affect_uuids:
                process_affect.delay(
                    affect_uuid=affect_uuid,
                    groups_read=settings.PUBLIC_READ_GROUPS,
                    groups_write=[settings.PUBLIC_WRITE_GROUP],
                )
