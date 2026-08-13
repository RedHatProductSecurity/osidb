from datetime import datetime, timedelta, timezone

import pytest
from django.test import TestCase
from freezegun import freeze_time

from osidb.sync_manager import (
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


class TestSyncManagerFailed(TestCase):
    """Test cases for SyncManager.failed() method"""

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_raises_exception(self):
        flaw = FlawFactory(embargoed=False)

        SyncManager.objects.create(name=SyncManager.__name__, sync_id=flaw.uuid)

        test_exception = RuntimeError("Test error")

        with pytest.raises(RuntimeError, match="Test error"):
            SyncManager.failed(flaw.uuid, test_exception)

        # Verify the failure was recorded even though it was raised
        manager = SyncManager.objects.get(name=SyncManager.__name__, sync_id=flaw.uuid)
        assert manager.last_failed_reason == "Test error"
        assert manager.last_failed_dt is not None

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_permanent_sets_flag(self):
        flaw = FlawFactory(embargoed=False)

        SyncManager.objects.create(name=SyncManager.__name__, sync_id=flaw.uuid)

        test_exception = RuntimeError("Data not found")

        with pytest.raises(RuntimeError, match="Data not found"):
            SyncManager.failed(flaw.uuid, test_exception, permanent=True)

        # Verify permanent flag is set
        manager = SyncManager.objects.get(name=SyncManager.__name__, sync_id=flaw.uuid)
        assert manager.permanently_failed is True
        assert manager.last_failed_reason == "Data not found"

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_updates_consecutive_failures(self):
        flaw = FlawFactory(embargoed=False)

        manager = SyncManager.objects.create(
            name=SyncManager.__name__,
            sync_id=flaw.uuid,
            last_consecutive_failures=2,
        )

        with pytest.raises(RuntimeError):
            SyncManager.failed(flaw.uuid, RuntimeError("Test"))

        manager.refresh_from_db()
        assert manager.last_consecutive_failures == 3
        assert manager.last_consecutive_reschedules == 0  # Should be reset

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_becomes_permanent_after_max_failures(self):
        flaw = FlawFactory(embargoed=False)

        # Set to the threshold (MAX_CONSECUTIVE_FAILURES is 5)
        # The code checks the current value before incrementing, so at 5 it becomes permanent
        manager = SyncManager.objects.create(
            name=SyncManager.__name__,
            sync_id=flaw.uuid,
            last_consecutive_failures=5,
        )

        with pytest.raises(RuntimeError):
            SyncManager.failed(flaw.uuid, RuntimeError("Final failure"))

        manager.refresh_from_db()
        assert manager.last_consecutive_failures == 6
        # Verify it becomes permanent when at or above threshold
        assert manager.permanently_failed is True
