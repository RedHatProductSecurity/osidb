from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from celery.exceptions import Ignore
from django.test import TestCase
from freezegun import freeze_time

from osidb.sync_manager import (
    JiraTaskDownloadManager,
    JiraTaskSyncManager,
    JiraTaskTransitionManager,
    SyncManager,
)
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


class TestSyncManager(TestCase):
    """
    Test cases for SyncManager and its subclasses.
    Created to hunt down issues with Flaw data reset.
    """

    @freeze_time(datetime(2025, 6, 24))
    def test_is_in_progress(self):
        flaw = FlawFactory(embargoed=False)

        sync_manager = SyncManager.objects.create(
            name=SyncManager.__name__, sync_id=flaw.uuid
        )
        sync_manager.last_scheduled_dt = datetime.now(timezone.utc)
        sync_manager.last_started_dt = datetime.now(timezone.utc)
        sync_manager.save()

        assert sync_manager.is_in_progress(flaw.uuid)

        sync_manager.last_finished_dt = datetime.now(timezone.utc) + timedelta(
            seconds=5
        )
        sync_manager.save()

        assert not sync_manager.is_in_progress(flaw.uuid)

    @freeze_time(datetime(2025, 6, 24))
    def test_is_scheduled(self):
        flaw = FlawFactory(embargoed=False)

        sync_manager = SyncManager.objects.create(
            name=SyncManager.__name__, sync_id=flaw.uuid
        )
        sync_manager.last_scheduled_dt = datetime.now(timezone.utc)
        sync_manager.save()

        assert sync_manager.is_scheduled(flaw.uuid)

        sync_manager.last_started_dt = datetime.now(timezone.utc)
        sync_manager.save()

        assert not sync_manager.is_scheduled(flaw.uuid)

        sync_manager.last_rescheduled_dt = datetime.now(timezone.utc) + timedelta(
            seconds=5
        )
        sync_manager.save()

        assert sync_manager.is_scheduled(flaw.uuid)

        sync_manager.last_finished_dt = datetime.now(timezone.utc) + timedelta(
            seconds=6
        )
        sync_manager.last_scheduled_dt = datetime.now(timezone.utc) + timedelta(
            seconds=10
        )
        sync_manager.save()

        assert sync_manager.is_scheduled(flaw.uuid)

        sync_manager.last_scheduled_dt = datetime.now(timezone.utc) + timedelta(
            seconds=1
        )
        sync_manager.last_rescheduled_dt = datetime.now(timezone.utc) + timedelta(
            seconds=1
        )
        sync_manager.last_consecutive_reschedules = 1
        sync_manager.last_started_dt = datetime.now(timezone.utc) + timedelta(seconds=2)
        sync_manager.last_finished_dt = datetime.now(timezone.utc) + timedelta(
            seconds=3
        )
        sync_manager.save()

        assert sync_manager.is_scheduled(flaw.uuid)

    @freeze_time(datetime(2025, 6, 24))
    def test_jira_task_transition_manager_reschedule(self):
        flaw = FlawFactory(embargoed=False)

        transition_manager = JiraTaskTransitionManager.objects.create(
            name=JiraTaskTransitionManager.__name__, sync_id=flaw.uuid
        )

        # simulate schedule call
        transition_manager.last_scheduled_dt = datetime.now(timezone.utc)
        transition_manager.last_started_dt = datetime.now(timezone.utc) + timedelta(
            seconds=1
        )
        transition_manager.save()

        # schedule second call
        with self.captureOnCommitCallbacks(execute=False):
            with freeze_time(datetime(2025, 6, 24) + timedelta(seconds=5)):
                JiraTaskTransitionManager.schedule(flaw.uuid)

        transition_manager2 = JiraTaskTransitionManager.objects.get(
            name=JiraTaskTransitionManager.__name__, sync_id=flaw.uuid
        )

        assert transition_manager2.last_consecutive_reschedules == 1
        assert transition_manager2.last_rescheduled_reason == "Task already in progress"
        assert (
            transition_manager2.last_scheduled_dt > transition_manager.last_scheduled_dt
        )

    @freeze_time(datetime(2025, 6, 24))
    def test_jira_task_download_manager_conflicting_idle(self):
        flaw = FlawFactory(embargoed=False)

        download_manager = JiraTaskDownloadManager.objects.create(
            name=JiraTaskDownloadManager.__name__, sync_id=flaw.task_key
        )

        # Raises an exception if conflicting sync managers are found
        download_manager.check_conflicting_sync_managers(
            flaw.task_key, Mock(), [JiraTaskTransitionManager, JiraTaskSyncManager]
        )

    @freeze_time(datetime(2025, 6, 24))
    def test_jira_task_download_manager_conflicting_running(self):
        flaw = FlawFactory(embargoed=False)

        download_manager = JiraTaskDownloadManager.objects.create(
            name=JiraTaskDownloadManager.__name__, sync_id=flaw.task_key
        )
        transition_manager = JiraTaskTransitionManager.objects.create(
            name=JiraTaskTransitionManager.__name__, sync_id=flaw.uuid
        )

        transition_manager.last_scheduled_dt = datetime.now(timezone.utc)
        transition_manager.last_started_dt = datetime.now(timezone.utc)
        transition_manager.save()

        with pytest.raises(Ignore):
            download_manager.check_conflicting_sync_managers(
                flaw.task_key, Mock(), [JiraTaskTransitionManager, JiraTaskSyncManager]
            )

    @freeze_time(datetime(2025, 6, 24))
    def test_jira_task_download_manager_conflicting_scheduled(self):
        flaw = FlawFactory(embargoed=False)

        download_manager = JiraTaskDownloadManager.objects.create(
            name=JiraTaskDownloadManager.__name__, sync_id=flaw.task_key
        )
        transition_manager = JiraTaskTransitionManager.objects.create(
            name=JiraTaskTransitionManager.__name__, sync_id=flaw.uuid
        )

        transition_manager.last_scheduled_dt = datetime.now(timezone.utc) + timedelta(
            seconds=1
        )
        transition_manager.last_rescheduled_dt = datetime.now(timezone.utc) + timedelta(
            seconds=1
        )
        transition_manager.last_consecutive_reschedules = 1
        transition_manager.last_started_dt = datetime.now(timezone.utc) + timedelta(
            seconds=2
        )
        transition_manager.last_finished_dt = datetime.now(timezone.utc) + timedelta(
            seconds=3
        )
        transition_manager.save()

        with pytest.raises(Ignore):
            download_manager.check_conflicting_sync_managers(
                flaw.task_key, Mock(), [JiraTaskTransitionManager, JiraTaskSyncManager]
            )
