from datetime import UTC, datetime, timedelta

import pytest
from django.test import TestCase
from freezegun import freeze_time
from rhubarb.tasks import LockableTaskWithArgs

from osidb.sync_manager import (
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
        sync_manager.last_scheduled_dt = datetime.now(UTC)
        sync_manager.last_started_dt = datetime.now(UTC)
        sync_manager.save()

        assert sync_manager.is_in_progress(flaw.uuid)

        sync_manager.last_finished_dt = datetime.now(UTC) + timedelta(seconds=5)
        sync_manager.save()

        assert not sync_manager.is_in_progress(flaw.uuid)

    @freeze_time(datetime(2025, 6, 24))
    def test_is_scheduled(self):
        flaw = FlawFactory(embargoed=False)

        sync_manager = SyncManager.objects.create(
            name=SyncManager.__name__, sync_id=flaw.uuid
        )
        sync_manager.last_scheduled_dt = datetime.now(UTC)
        sync_manager.save()

        assert sync_manager.is_scheduled(flaw.uuid)

        sync_manager.last_started_dt = datetime.now(UTC)
        sync_manager.save()

        assert not sync_manager.is_scheduled(flaw.uuid)

        sync_manager.last_rescheduled_dt = datetime.now(UTC) + timedelta(seconds=5)
        sync_manager.save()

        assert sync_manager.is_scheduled(flaw.uuid)

        sync_manager.last_finished_dt = datetime.now(UTC) + timedelta(seconds=6)
        sync_manager.last_scheduled_dt = datetime.now(UTC) + timedelta(seconds=10)
        sync_manager.save()

        assert sync_manager.is_scheduled(flaw.uuid)

        sync_manager.last_scheduled_dt = datetime.now(UTC) + timedelta(seconds=1)
        sync_manager.last_rescheduled_dt = datetime.now(UTC) + timedelta(seconds=1)
        sync_manager.last_consecutive_reschedules = 1
        sync_manager.last_started_dt = datetime.now(UTC) + timedelta(seconds=2)
        sync_manager.last_finished_dt = datetime.now(UTC) + timedelta(seconds=3)
        sync_manager.save()

        assert sync_manager.is_scheduled(flaw.uuid)

    @freeze_time(datetime(2025, 6, 24))
    def test_is_scheduled_after_failure(self):
        """
        is_scheduled() must treat last_failed_dt as a completion marker,
        the same way it already treats last_finished_dt: a schedule that
        predates the failure must not count as "still scheduled" (or a
        failed run would leave the manager permanently scheduled/looping),
        and a schedule made after the failure must.
        """
        flaw = FlawFactory(embargoed=False)

        sync_manager = SyncManager.objects.create(
            name=SyncManager.__name__, sync_id=flaw.uuid
        )
        sync_manager.last_scheduled_dt = datetime.now(UTC)
        sync_manager.last_started_dt = datetime.now(UTC) + timedelta(seconds=1)
        sync_manager.save()

        # the run fails without ever finishing
        sync_manager.last_failed_dt = datetime.now(UTC) + timedelta(seconds=5)
        sync_manager.save()

        # the schedule predates the failure: must not look "still scheduled"
        assert not sync_manager.is_scheduled(flaw.uuid)

        # a schedule() call after the failure must count as freshly scheduled
        sync_manager.last_scheduled_dt = datetime.now(UTC) + timedelta(seconds=10)
        sync_manager.save()

        assert sync_manager.is_scheduled(flaw.uuid)

    @freeze_time(datetime(2025, 6, 24))
    def test_jira_task_transition_manager_reschedule(self):
        flaw = FlawFactory(embargoed=False)

        transition_manager = JiraTaskTransitionManager.objects.create(
            name=JiraTaskTransitionManager.__name__, sync_id=flaw.uuid
        )

        # simulate schedule call
        transition_manager.last_scheduled_dt = datetime.now(UTC)
        transition_manager.last_started_dt = datetime.now(UTC) + timedelta(seconds=1)
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
    def test_jira_task_sync_manager_reschedule(self):
        """
        A flaw save that arrives while a JiraTaskSyncManager run is already
        in progress for the same flaw must be collapsed into a reschedule
        instead of enqueuing a second, redundant Celery task.
        """
        flaw = FlawFactory(embargoed=False)

        sync_manager = JiraTaskSyncManager.objects.create(
            name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
        )

        # simulate schedule call
        sync_manager.last_scheduled_dt = datetime.now(UTC)
        sync_manager.last_started_dt = datetime.now(UTC) + timedelta(seconds=1)
        sync_manager.save()

        # schedule second call while the first is still running
        with self.captureOnCommitCallbacks(execute=False):
            with freeze_time(datetime(2025, 6, 24) + timedelta(seconds=5)):
                JiraTaskSyncManager.schedule(flaw.uuid)

        sync_manager2 = JiraTaskSyncManager.objects.get(
            name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
        )

        assert sync_manager2.last_consecutive_reschedules == 1
        assert sync_manager2.last_rescheduled_reason == "Task already in progress"
        assert sync_manager2.last_scheduled_dt > sync_manager.last_scheduled_dt

    @freeze_time(datetime(2025, 6, 24))
    def test_jira_task_sync_manager_no_duplicate_on_third_schedule(self):
        """
        A third schedule() call arriving while a reschedule is already
        pending (the task is still in progress from the first run, and a
        retry was already deferred by a second call) must be a no-op: it
        must not enqueue yet another Celery task on top of the one already
        deferred.
        """
        flaw = FlawFactory(embargoed=False)

        sync_manager = JiraTaskSyncManager.objects.create(
            name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
        )

        # first run starts
        sync_manager.last_scheduled_dt = datetime.now(UTC)
        sync_manager.last_started_dt = datetime.now(UTC) + timedelta(seconds=1)
        sync_manager.save()

        # second call while the first run is still in progress: this must
        # defer a single retry
        with freeze_time(datetime(2025, 6, 24) + timedelta(seconds=5)):
            with self.captureOnCommitCallbacks(execute=False) as callbacks:
                JiraTaskSyncManager.schedule(flaw.uuid)
        assert len(callbacks) == 1

        # third call while the deferred retry is still pending: must not
        # queue an additional task
        with freeze_time(datetime(2025, 6, 24) + timedelta(seconds=10)):
            with self.captureOnCommitCallbacks(execute=False) as callbacks:
                JiraTaskSyncManager.schedule(flaw.uuid)
        assert len(callbacks) == 0

        sync_manager2 = JiraTaskSyncManager.objects.get(
            name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
        )
        # no extra reschedule was recorded for the third, no-op call either
        assert sync_manager2.last_consecutive_reschedules == 1

    @freeze_time(datetime(2025, 6, 24))
    def test_jira_task_sync_manager_schedules_after_failed_run(self):
        """
        Regression test for the bug that forced the OSIDB-5189 revert:
        after a failed run, is_scheduled() only checked last_finished_dt,
        so schedule() silently no-op'd instead of enqueuing a new run.
        A schedule() call after a failure must actually enqueue.
        """
        flaw = FlawFactory(embargoed=False)

        sync_manager = JiraTaskSyncManager.objects.create(
            name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
        )
        sync_manager.last_scheduled_dt = datetime.now(UTC)
        sync_manager.last_started_dt = datetime.now(UTC) + timedelta(seconds=1)
        sync_manager.save()

        # the run fails without ever finishing
        with freeze_time(datetime(2025, 6, 24) + timedelta(seconds=2)):
            SyncManager.objects.filter(
                name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
            ).update(last_failed_dt=datetime.now(UTC), last_consecutive_failures=1)

        # a later schedule() call must enqueue a new task, not silently skip
        with freeze_time(datetime(2025, 6, 24) + timedelta(seconds=10)):
            with self.captureOnCommitCallbacks(execute=False) as callbacks:
                JiraTaskSyncManager.schedule(flaw.uuid)

        assert len(callbacks) == 1

        sync_manager2 = JiraTaskSyncManager.objects.get(
            name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
        )
        # this was a fresh schedule, not a reschedule
        assert sync_manager2.last_consecutive_reschedules == 0
        assert sync_manager2.last_scheduled_dt > sync_manager.last_scheduled_dt


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


class TestCheckForReschedules(TestCase):
    """
    check_for_reschedules()'s scheduled_not_started bucket must recover
    EXCLUSIVE-mode managers (whose lock-rejected duplicates can bump
    last_scheduled_dt past last_started_dt on a genuinely stuck run) on
    the MAX_RUN_LENGTH timescale, not the much longer MAX_SCHEDULE_DELAY
    meant for plain broker-delivery backlogs.
    """

    @freeze_time(datetime(2025, 6, 24))
    def test_scheduled_not_started_recovers_sooner_for_exclusive_managers(self):
        flaw = FlawFactory(embargoed=False)

        manager = JiraTaskSyncManager.objects.create(
            name=JiraTaskSyncManager.__name__,
            sync_id=flaw.uuid,
            last_started_dt=datetime.now(UTC),
        )
        # a lock-rejected duplicate bumped last_scheduled_dt past
        # last_started_dt without the original (stuck) run ever calling
        # started() again
        manager.last_scheduled_dt = (
            datetime.now(UTC)
            + JiraTaskSyncManager.MAX_RUN_LENGTH
            + timedelta(minutes=1)
        )
        manager.save()

        # well past MAX_RUN_LENGTH since that scheduled_dt, still nowhere
        # near MAX_SCHEDULE_DELAY
        with freeze_time(datetime(2025, 6, 24) + timedelta(hours=3)):
            with self.captureOnCommitCallbacks(execute=False) as callbacks:
                JiraTaskSyncManager.check_for_reschedules()

        assert len(callbacks) == 1
        manager.refresh_from_db()
        assert manager.last_consecutive_reschedules == 1

    @freeze_time(datetime(2025, 6, 24))
    def test_scheduled_not_started_keeps_full_delay_for_non_exclusive_managers(self):
        flaw = FlawFactory(embargoed=False)

        manager = SyncManager.objects.create(
            name=SyncManager.__name__,
            sync_id=flaw.uuid,
            last_started_dt=datetime.now(UTC),
        )
        manager.last_scheduled_dt = (
            datetime.now(UTC) + SyncManager.MAX_RUN_LENGTH + timedelta(minutes=1)
        )
        manager.save()

        # past MAX_RUN_LENGTH but well short of MAX_SCHEDULE_DELAY: a
        # non-EXCLUSIVE manager has no lock-rejection path, so it keeps
        # the original, more lenient broker-backlog threshold
        with freeze_time(datetime(2025, 6, 24) + timedelta(hours=3)):
            with self.captureOnCommitCallbacks(execute=False) as callbacks:
                SyncManager.check_for_reschedules()

        assert len(callbacks) == 0


class TestJiraTaskSyncManagerLockContention:
    """
    RetryOnLockContention turned lock contention into Celery-level
    retries every 30s (up to ~130/task), re-enqueuing into the fifo.*
    queues faster than the two concurrency-1 workers could drain them.
    JiraTaskSyncManager.sync_task must not use any such
    retry-on-contention wrapper: lock contention must be dropped
    (LockableTaskWithArgs' plain behaviour), not retried.
    """

    def test_sync_task_uses_plain_lockable_task_with_args(self):
        task = JiraTaskSyncManager.sync_task

        assert isinstance(task, LockableTaskWithArgs)
        # No custom before_start override anywhere between the task class
        # and LockableTaskWithArgs: lock contention propagates as-is
        # (ConcurrentExecutionException / Reject, no requeue) instead of
        # being converted into a Celery retry.
        assert task.before_start.__func__ is LockableTaskWithArgs.before_start
