from celery import shared_task
from celery.schedules import crontab
from django.utils import timezone

from config.settings import CELERY_BEAT_SCHEDULE

from .constants import JIRA_SERVICE_TOKEN
from .models import ScheduledClosingTask
from .service import JiraTaskmanQuerier, TaskResolution, TaskStatus


@shared_task
def close_unchanged_published_tasks():
    name = "apps.taskman.tasks.close_unchanged_published_tasks"
    CELERY_BEAT_SCHEDULE[name] = {
        "task": name,
        "schedule": crontab(hour=15, minute=20),
    }

    today = timezone.now()
    jira_tasks = ScheduledClosingTask.objects.filter(scheduled_dt__lt=today)

    done_tasks = []

    jira = JiraTaskmanQuerier(JIRA_SERVICE_TOKEN)
    for jira_task in jira_tasks:
        res = jira.update_task_status(
            jira_task.task_key, TaskStatus.CLOSED, TaskResolution.DONE
        )
        if res.status_code == 200:
            done_tasks.append(jira_task.task_key)

    ScheduledClosingTask.objects.filter(task_key__in=done_tasks).delete()
