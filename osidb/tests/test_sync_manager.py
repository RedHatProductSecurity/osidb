import threading
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from django.db import connection, transaction
from django.db.utils import OperationalError
from django.test import TestCase, TransactionTestCase
from freezegun import freeze_time

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
            last_scheduled_dt=datetime.now(UTC),
            last_started_dt=datetime.now(UTC),
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
                with connection.cursor() as cursor:
                    cursor.execute("SET lock_timeout = '2s'")
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

        manager = JiraTaskSyncManager.objects.get(
            name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
        )
        # Exactly one reschedule was recorded (the loser of the race
        # deferred instead of enqueuing its own duplicate).
        assert manager.last_consecutive_reschedules == 1
        # ...and it carries the deferred-retry countdown, not an immediate
        # apply_async().
        assert enqueued[0][1]["countdown"] == JiraTaskSyncManager.COUNTDOWN

    def test_concurrent_reschedule_calls_do_not_lose_updates(self):
        """
        reschedule() is also called standalone (unlocked, before this
        fix) by check_for_reschedules()'s periodic sweep, which can race
        a concurrent reschedule()/schedule() call for the same sync_id.
        Without the same row lock schedule() uses, two concurrent
        reschedule() calls could both read last_consecutive_reschedules=0
        and both write 1 - a lost update.
        """
        flaw = FlawFactory(embargoed=False)

        JiraTaskSyncManager.objects.create(
            name=JiraTaskSyncManager.__name__,
            sync_id=flaw.uuid,
            last_scheduled_dt=datetime.now(UTC),
            last_started_dt=datetime.now(UTC),
        )

        original_enqueue = JiraTaskSyncManager._enqueue.__func__

        def slow_enqueue(cls, sync_id, *args, **kwargs):
            # _enqueue() runs inside reschedule()'s locked section, after
            # the last_consecutive_reschedules read-modify-write: holding
            # it open here keeps the row lock held long enough that the
            # other thread's select_for_update() clearly blocks on it
            # instead of racing past.
            result = original_enqueue(cls, sync_id, *args, **kwargs)
            time.sleep(0.2)
            return result

        enqueued = []

        def fake_apply_async(*args, **kwargs):
            enqueued.append((args, kwargs))

        errors = []

        def worker():
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET lock_timeout = '2s'")
                JiraTaskSyncManager.reschedule(flaw.uuid, "test reschedule")
            except Exception as e:
                errors.append(e)
            finally:
                connection.close()

        with (
            patch.object(JiraTaskSyncManager, "_enqueue", classmethod(slow_enqueue)),
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

        manager = JiraTaskSyncManager.objects.get(
            name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
        )
        # Without the lock, both threads could read
        # last_consecutive_reschedules=0 and both write 1.
        assert manager.last_consecutive_reschedules == 2
        assert len(enqueued) == 2

    def test_schedule_lock_wait_times_out_instead_of_blocking_forever(self):
        """
        schedule()'s row lock wait is bounded by LOCK_WAIT_TIMEOUT: if
        whoever else holds the lock (e.g. a stalled request transaction)
        never releases it, schedule() must fail fast and log instead of
        blocking the caller's thread/connection indefinitely.
        """
        flaw = FlawFactory(embargoed=False)

        JiraTaskSyncManager.objects.create(
            name=JiraTaskSyncManager.__name__,
            sync_id=flaw.uuid,
        )

        lock_acquired = threading.Event()
        release_lock = threading.Event()

        def hold_lock():
            with transaction.atomic():
                list(
                    JiraTaskSyncManager.objects.select_for_update().filter(
                        name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
                    )
                )
                lock_acquired.set()
                release_lock.wait(timeout=5)
            connection.close()

        holder = threading.Thread(target=hold_lock)
        holder.start()
        assert lock_acquired.wait(timeout=5), "lock holder never acquired the row lock"

        errors = []

        def waiter():
            try:
                with patch.object(JiraTaskSyncManager, "LOCK_WAIT_TIMEOUT", "200ms"):
                    JiraTaskSyncManager.schedule(flaw.uuid)
            except Exception as e:
                errors.append(e)
            finally:
                connection.close()

        with self.assertLogs("osidb.sync_manager", level="WARNING") as logs:
            t = threading.Thread(target=waiter)
            t.start()
            t.join(timeout=5)

        release_lock.set()
        holder.join(timeout=5)

        assert not t.is_alive(), "waiter thread did not finish"
        assert not holder.is_alive(), "lock holder thread did not finish"
        assert len(errors) == 1
        assert isinstance(errors[0], OperationalError)
        assert any("Timed out waiting" in message for message in logs.output)

    def test_reschedule_lock_wait_times_out_instead_of_blocking_forever(self):
        """
        reschedule()'s row lock wait is bounded the same way schedule()'s
        is: check_for_reschedules() calls it in a loop over every sync_id
        in one sweep, so an unbounded wait on one stuck row would stall
        every other flaw behind it.
        """
        flaw = FlawFactory(embargoed=False)

        JiraTaskSyncManager.objects.create(
            name=JiraTaskSyncManager.__name__,
            sync_id=flaw.uuid,
        )

        lock_acquired = threading.Event()
        release_lock = threading.Event()

        def hold_lock():
            with transaction.atomic():
                list(
                    JiraTaskSyncManager.objects.select_for_update().filter(
                        name=JiraTaskSyncManager.__name__, sync_id=flaw.uuid
                    )
                )
                lock_acquired.set()
                release_lock.wait(timeout=5)
            connection.close()

        holder = threading.Thread(target=hold_lock)
        holder.start()
        assert lock_acquired.wait(timeout=5), "lock holder never acquired the row lock"

        errors = []

        def waiter():
            try:
                with patch.object(JiraTaskSyncManager, "LOCK_WAIT_TIMEOUT", "200ms"):
                    JiraTaskSyncManager.reschedule(flaw.uuid, "test reschedule")
            except Exception as e:
                errors.append(e)
            finally:
                connection.close()

        with self.assertLogs("osidb.sync_manager", level="WARNING") as logs:
            t = threading.Thread(target=waiter)
            t.start()
            t.join(timeout=5)

        release_lock.set()
        holder.join(timeout=5)

        assert not t.is_alive(), "waiter thread did not finish"
        assert not holder.is_alive(), "lock holder thread did not finish"
        assert len(errors) == 1
        assert isinstance(errors[0], OperationalError)
        assert any("Timed out waiting" in message for message in logs.output)

    def test_schedule_lock_timeout_does_not_leak_into_caller_transaction(self):
        """
        SET LOCAL lock_timeout only reverts at the end of the *outer*
        transaction (or on rollback), not when schedule()'s own inner
        atomic()/savepoint is released. It must be explicitly reset after
        a successful lock acquisition, or it leaks into whatever else
        runs in the same outer transaction afterwards - e.g. schedule()
        called from inside Flaw.save() under ATOMIC_REQUESTS, where an
        unrelated later query that legitimately needs to wait on a lock
        longer than LOCK_WAIT_TIMEOUT would now fail instead of waiting.
        """
        flaw = FlawFactory(embargoed=False)

        with patch.object(JiraTaskSyncManager.sync_task, "apply_async"):
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute("SHOW lock_timeout")
                    (before,) = cursor.fetchone()

                JiraTaskSyncManager.schedule(flaw.uuid)

                with connection.cursor() as cursor:
                    cursor.execute("SHOW lock_timeout")
                    (after,) = cursor.fetchone()

        assert after == before

    def test_burst_of_schedule_calls_enqueues_exactly_once(self):
        """
        Proxy for "a burst of saves collapses into one queued/in-flight
        task": simulates a larger burst than a single race window
        (concurrent schedule() calls for the same flaw while a run is
        already in progress) and asserts it still collapses to exactly one
        enqueue, i.e. the fifo.* queue depth for this flaw doesn't grow
        with the size of the burst.

        Worker count is kept modest (rather than e.g. 20) to stay well
        under CI's DB connection limit - each thread opens its own
        connection - and each worker sets a short lock_timeout so that if
        the row lock is ever held longer than expected (a regression),
        the blocked schedule() call fails fast instead of the thread
        hanging past its join() timeout and surviving into teardown.
        """
        flaw = FlawFactory(embargoed=False)

        JiraTaskSyncManager.objects.create(
            name=JiraTaskSyncManager.__name__,
            sync_id=flaw.uuid,
            last_scheduled_dt=datetime.now(UTC),
            last_started_dt=datetime.now(UTC),
        )

        enqueued = []

        def fake_apply_async(*args, **kwargs):
            enqueued.append((args, kwargs))

        errors = []

        def worker():
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET lock_timeout = '2s'")
                JiraTaskSyncManager.schedule(flaw.uuid)
            except Exception as e:
                errors.append(e)
            finally:
                connection.close()

        with patch.object(
            JiraTaskSyncManager.sync_task, "apply_async", side_effect=fake_apply_async
        ):
            threads = [threading.Thread(target=worker) for _ in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

        assert all(not t.is_alive() for t in threads), "a worker thread did not finish"
        assert not errors, f"worker thread(s) raised: {errors}"
        assert len(enqueued) == 1
