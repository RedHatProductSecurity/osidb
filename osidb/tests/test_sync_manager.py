import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from celery.exceptions import Retry
from django.db import connection
from django.test import TestCase, TransactionTestCase
from freezegun import freeze_time
from rhubarb.exceptions import ConcurrentExecutionException
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
    def test_jira_task_sync_manager_reschedule(self):
        """
        A flaw save that arrives while a JiraTaskSyncManager run is already
        in progress for the same flaw must be collapsed into a reschedule
        instead of enqueuing a second, redundant Celery task (OSIDB latency
        investigation: duplicate schedules were stacking up on the shared
        queue).
        """
        flaw = FlawFactory(embargoed=False)

        sync_manager = JiraTaskSyncManager.objects.create(
            name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
        )

        # simulate schedule call
        sync_manager.last_scheduled_dt = datetime.now(timezone.utc)
        sync_manager.last_started_dt = datetime.now(timezone.utc) + timedelta(seconds=1)
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
        sync_manager.last_scheduled_dt = datetime.now(timezone.utc)
        sync_manager.last_started_dt = datetime.now(timezone.utc) + timedelta(seconds=1)
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


class TestSyncManagerConcurrency(TransactionTestCase):
    """
    Exercises the select_for_update() locking added to schedule() for
    EXCLUSIVE-mode managers. This needs real, separately-committed
    transactions on two threads to observe actual blocking, so it can't
    use the savepoint-based TestCase like the rest of this file.
    """

    def test_concurrent_schedule_calls_do_not_double_enqueue(self):
        flaw = FlawFactory(embargoed=False)

        JiraTaskSyncManager.objects.create(
            name=JiraTaskSyncManager.__name__,
            sync_id=flaw.uuid,
            last_scheduled_dt=datetime.now(timezone.utc),
            last_started_dt=datetime.now(timezone.utc),
        )

        original_is_scheduled = JiraTaskSyncManager.is_scheduled.__func__

        def slow_is_scheduled(cls, sync_id):
            # Holds the row lock (already acquired by schedule() before
            # this call) long enough that, without select_for_update(),
            # the other thread would clearly race past this check instead
            # of blocking on it.
            result = original_is_scheduled(cls, sync_id)
            time.sleep(0.2)
            return result

        enqueued = []

        def fake_apply_async(*args, **kwargs):
            enqueued.append((args, kwargs))

        errors = []

        def worker():
            try:
                JiraTaskSyncManager.schedule(flaw.uuid)
            except Exception as e:
                # Captured so the test fails loudly instead of a bare
                # threading.Thread swallowing it silently.
                errors.append(e)
            finally:
                # Each thread gets its own DB connection; nothing else
                # closes it once the thread exits.
                connection.close()

        with (
            patch.object(
                JiraTaskSyncManager, "is_scheduled", classmethod(slow_is_scheduled)
            ),
            patch.object(
                JiraTaskSyncManager.sync_task,
                "apply_async",
                side_effect=fake_apply_async,
            ),
        ):
            threads = [threading.Thread(target=worker) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)

        assert all(not t.is_alive() for t in threads), "a worker thread did not finish"
        assert not errors, f"worker thread(s) raised: {errors}"

        # Without select_for_update(), both threads could pass the
        # is_scheduled()/is_in_progress() checks before either write
        # landed, and both would enqueue a deferred retry - the exact
        # duplicate-enqueue bug the lock closes.
        assert len(enqueued) == 1


class TestRetryOnLockContention:
    def test_before_start_retries_instead_of_dropping_on_lock_contention(self):
        """
        LockableTaskWithArgs.before_start() raises ConcurrentExecutionException
        (a Reject, requeue=False) when it can't acquire the lock, which
        Celery just drops - no retry. RetryOnLockContention must convert
        that into a Celery Retry instead, so recovery doesn't wait for the
        24h check_for_reschedules() safety net.
        """
        task = JiraTaskSyncManager.sync_task
        task.push_request(
            called_directly=False,
            retries=0,
            id="task-id",
            args=("some-flaw-uuid",),
            kwargs={},
        )
        try:
            with (
                patch.object(
                    LockableTaskWithArgs,
                    "before_start",
                    side_effect=ConcurrentExecutionException("locked"),
                ),
                # retry() re-publishes the task itself; avoid needing a
                # live broker for what we're actually asserting here.
                patch.object(task, "apply_async"),
                pytest.raises(Retry) as exc_info,
            ):
                task.before_start("task-id", ("some-flaw-uuid",), {})

            assert exc_info.value.when == task.default_retry_delay
        finally:
            task.pop_request()
