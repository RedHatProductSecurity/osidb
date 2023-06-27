"""
Tests of scheduled tasks of Taskman
"""
from datetime import timedelta

import pytest
from django.utils import timezone
from freezegun import freeze_time
from requests import Response

from apps.taskman.models import ScheduledClosingTask
from apps.taskman.service import JiraTaskmanQuerier
from apps.taskman.tasks import close_unchanged_published_tasks

pytestmark = pytest.mark.unit


class TestScheduledClosingTask(object):
    @freeze_time(timezone.datetime(2099, 5, 26))
    def test_close_unchanged_published_tasks(self, monkeypatch):
        """Test that celery delete expired tasks after success"""

        def mock_update_task_status(self, issue_key, status, resolution=None):
            response = Response()
            response.status_code = 200
            return response

        monkeypatch.setattr(
            JiraTaskmanQuerier, "update_task_status", mock_update_task_status
        )

        today = timezone.now()
        ScheduledClosingTask.objects.create(
            scheduled_dt=today - timedelta(days=1), task_key="OSIM-1"
        )
        ScheduledClosingTask.objects.create(
            scheduled_dt=today + timedelta(days=1), task_key="OSIM-2"
        )

        close_unchanged_published_tasks.apply()

        assert not ScheduledClosingTask.objects.filter(task_key="OSIM-1").exists()
        assert ScheduledClosingTask.objects.filter(task_key="OSIM-2").exists()
