"""
feed collector celery tasks
"""
from celery.schedules import crontab
from celery.utils.log import get_task_logger

from collectors.framework.models import collector

from .collectors import FeedCollector

logger = get_task_logger(__name__)


@collector(
    base=FeedCollector,
    # Execute once a day
    crontab=crontab(minute=40, hour=2),
    depends_on=["collectors.bzimport.tasks.flaw_collector"],
)
def feed_collector(collector_obj):
    msg = collector_obj.collect()
    return f"{msg}"
