import json
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from django.test import TestCase
from freezegun import freeze_time
from rhubarb.tasks import LockableTaskWithArgs

from osidb.models import Affect, Flaw, Impact, Tracker
from osidb.sync_manager import (
    BZTrackerDownloadManager,
    JiraTaskSyncManager,
    JiraTaskTransitionManager,
    JiraTrackerDownloadManager,
    SyncManager,
)
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

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
    retries every 30s (up to ~130/task), re-enqueuing tasks faster
    than workers could drain them (OSIDB-5189). JiraTaskSyncManager.sync_task
    must not use any such retry-on-contention wrapper: lock contention must
    be dropped (LockableTaskWithArgs' plain behaviour), not retried.
    """

    def test_sync_task_uses_plain_lockable_task_with_args(self):
        task = JiraTaskSyncManager.sync_task

        assert isinstance(task, LockableTaskWithArgs)
        # No custom before_start override anywhere between the task class
        # and LockableTaskWithArgs: lock contention propagates as-is
        # (ConcurrentExecutionException / Reject, no requeue) instead of
        # being converted into a Celery retry.
        assert task.before_start.__func__ is LockableTaskWithArgs.before_start


class TestLinkTrackerReclassification:
    """
    regression tests for OSIDB-5840

    during tracker sync the affect-tracker reconciliation
    (link_tracker_with_affects -> relink_affects) changes the links by plain
    bulk updates which fire no save signals, so nothing re-saved the flaw and
    a flaw sitting in PRE_SECONDARY_ASSESSMENT stalled there until some
    unrelated change re-saved it. The sync must re-run the workflow
    classification for the flaws of the relinked affects itself.
    """

    def _stream(self, bts_name="jboss"):
        # the tracker type must correspond to the BTS of the affect's module
        ps_module = PsModuleFactory(bts_name=bts_name)
        return PsUpdateStreamFactory(ps_module=ps_module)

    def _flaw(self, task_key="TASK-5840"):
        return FlawFactory(
            embargoed=False,
            task_key=task_key,
            impact=Impact.MODERATE,
            cwe_id="CWE-79",
            cve_description="a cve description",
        )

    def _resolved_affect(self, flaw, ps_update_stream, ps_component="component"):
        return AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component=ps_component,
        )

    def _unlinked_tracker(self, type_, ps_update_stream, external_system_id, meta_attr):
        # a freshly synced tracker has no affects linked yet - they get linked
        # by the following link_tracker_with_affects() call. The tracker model
        # would reject that state on save, so mirror what the collectors do
        # and save without raising.
        tracker = TrackerFactory.build(
            embargoed=False,
            type=type_,
            external_system_id=external_system_id,
            ps_update_stream=ps_update_stream.name,
            status="Open",
            resolution="",
            meta_attr=meta_attr,
        )
        tracker.save(raise_validation_error=False, auto_timestamps=False)
        return tracker

    def _jira_tracker(self, flaw, ps_update_stream, ps_component="component"):
        return self._unlinked_tracker(
            Tracker.TrackerType.JIRA,
            ps_update_stream,
            f"RHEL-5840-{ps_component}",
            {
                "labels": json.dumps([f"flaw:bz#{flaw.bz_id}"]),
                "ps_component": ps_component,
            },
        )

    def _bz_tracker(self, flaw, ps_update_stream, ps_component="component"):
        return self._unlinked_tracker(
            Tracker.TrackerType.BUGZILLA,
            ps_update_stream,
            f"584000-{ps_component}",
            {
                "blocks": json.dumps([flaw.bz_id]),
                "ps_component": ps_component,
                "whiteboard": "{}",
            },
        )

    @pytest.mark.enable_signals
    def test_jira_link_promotes_flaw_from_pre_secondary_assessment(self, monkeypatch):
        """
        linking the last missing tracker of a flaw sitting in
        PRE_SECONDARY_ASSESSMENT must immediately re-run the workflow
        classification and promote the flaw, with no flaw re-save at all
        """
        ps_update_stream = self._stream()
        flaw = self._flaw()
        affect = self._resolved_affect(flaw, ps_update_stream)
        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"
        assert flaw.resolved_dt is None

        tracker = self._jira_tracker(flaw, ps_update_stream)
        updated_dt = flaw.updated_dt

        def reject_flaw_save(instance, *args, **kwargs):
            pytest.fail("linking a tracker must not re-save the flaw")

        monkeypatch.setattr(Flaw, "save", reject_flaw_save)
        JiraTrackerDownloadManager.link_tracker_with_affects(tracker.external_system_id)

        flaw.refresh_from_db()
        # all affects resolved and tracked, and DONE has no requirements,
        # so the classifier passes SECONDARY_ASSESSMENT and lands in DONE
        assert flaw.workflow_name == "DEFAULT"
        assert flaw.workflow_state == "DONE"
        assert flaw.resolved_dt is not None
        # the mid-air collision timestamp must not move
        assert flaw.updated_dt == updated_dt
        affect.refresh_from_db()
        assert affect.tracker == tracker

        # the promotion is visible in the flaw audit trail
        event_model = Flaw.pgh_event_model
        assert event_model.objects.filter(
            pgh_obj_id=flaw.uuid, workflow_state="DONE"
        ).exists()

    @pytest.mark.enable_signals
    def test_bz_link_promotes_flaw_from_pre_secondary_assessment(self, monkeypatch):
        """
        the Bugzilla variant of the tracker download must reclassify the
        relinked flaws too (OSIDB-5840)
        """
        ps_update_stream = self._stream(bts_name="bugzilla")
        flaw = self._flaw()
        affect = self._resolved_affect(flaw, ps_update_stream)
        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        tracker = self._bz_tracker(flaw, ps_update_stream)
        updated_dt = flaw.updated_dt

        def reject_flaw_save(instance, *args, **kwargs):
            pytest.fail("linking a tracker must not re-save the flaw")

        monkeypatch.setattr(Flaw, "save", reject_flaw_save)
        BZTrackerDownloadManager.link_tracker_with_affects(tracker.external_system_id)

        flaw.refresh_from_db()
        assert flaw.workflow_state == "DONE"
        assert flaw.resolved_dt is not None
        assert flaw.updated_dt == updated_dt
        affect.refresh_from_db()
        assert affect.tracker == tracker

    @pytest.mark.enable_signals
    def test_link_unlink_regresses_flaw_from_done(self):
        """
        unlinking an affect during the reconciliation must re-run the
        classification too: a flaw regresses out of DONE once its last
        tracker link is withdrawn (OSIDB-5840)
        """
        ps_update_stream = self._stream(bts_name="bugzilla")
        flaw = self._flaw()
        affect = self._resolved_affect(flaw, ps_update_stream)
        tracker = TrackerFactory(
            embargoed=False,
            type=Tracker.TrackerType.BUGZILLA,
            external_system_id="584001",
            ps_update_stream=ps_update_stream.name,
            status="Open",
            resolution="",
            meta_attr={
                "blocks": json.dumps([flaw.bz_id]),
                "ps_component": "component",
                "whiteboard": "{}",
            },
            affects=[affect],
        )
        flaw.refresh_from_db()
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "DONE"
        assert flaw.resolved_dt is not None
        updated_dt = flaw.updated_dt

        # the flaw no longer blocks the tracker, so the next sync
        # reconciles the link away
        tracker.meta_attr["blocks"] = json.dumps([])
        tracker.save(raise_validation_error=False, auto_timestamps=False)
        BZTrackerDownloadManager.link_tracker_with_affects(tracker.external_system_id)

        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"
        # leaving DONE clears the resolution stamp
        assert flaw.resolved_dt is None
        # the mid-air collision timestamp must not move either
        assert flaw.updated_dt == updated_dt
        affect.refresh_from_db()
        assert affect.tracker is None

    @pytest.mark.enable_signals
    def test_relink_with_unchanged_links_leaves_flaw_untouched(self, monkeypatch):
        """
        flaws whose affect links did not change must not be touched at all:
        the common already-correct-links sync must neither reclassify the
        flaw nor re-save it (OSIDB-5840)
        """
        ps_update_stream = self._stream(bts_name="bugzilla")
        flaw = self._flaw()
        affect = self._resolved_affect(flaw, ps_update_stream)
        tracker = self._bz_tracker(flaw, ps_update_stream)
        tracker.affects.add(affect)
        flaw.refresh_from_db()
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "DONE"

        before = Flaw.objects.get(pk=flaw.pk)

        def reject_flaw_save(instance, *args, **kwargs):
            pytest.fail("unchanged tracker links must not re-save the flaw")

        monkeypatch.setattr(Flaw, "save", reject_flaw_save)
        BZTrackerDownloadManager.link_tracker_with_affects(tracker.external_system_id)

        after = Flaw.objects.get(pk=flaw.pk)
        assert after.workflow_state == "DONE"
        assert after.classification_meta == before.classification_meta
        assert after.resolved_dt == before.resolved_dt
        assert after.updated_dt == before.updated_dt
        assert after.last_validated_dt == before.last_validated_dt

    @pytest.mark.enable_signals
    def test_tracker_swap_with_stable_classification_leaves_flaw_untouched(
        self, monkeypatch
    ):
        """
        an affect moving between two relevant trackers changes its link but
        not the classification result - such a flaw must not be touched
        either, even though one of its affects was relinked (OSIDB-5840)
        """
        ps_update_stream = self._stream(bts_name="bugzilla")
        flaw = self._flaw()
        affect = self._resolved_affect(flaw, ps_update_stream)
        tracker1 = self._bz_tracker(flaw, ps_update_stream, ps_component="component")
        tracker1.affects.add(affect)
        flaw.refresh_from_db()
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "DONE"

        # a second relevant tracker for the same affect syncs in; when none
        # of the two is a duplicate the newly synced tracker wins the link
        tracker2 = self._unlinked_tracker(
            Tracker.TrackerType.BUGZILLA,
            ps_update_stream,
            "584002",
            {
                "blocks": json.dumps([flaw.bz_id]),
                "ps_component": "component",
                "whiteboard": "{}",
            },
        )
        before = Flaw.objects.get(pk=flaw.pk)

        def reject_flaw_save(instance, *args, **kwargs):
            pytest.fail("a classification-preserving relink must not re-save the flaw")

        monkeypatch.setattr(Flaw, "save", reject_flaw_save)
        BZTrackerDownloadManager.link_tracker_with_affects(tracker2.external_system_id)

        # the link really did change...
        affect.refresh_from_db()
        assert affect.tracker == tracker2
        # ...but the flaw was left untouched
        after = Flaw.objects.get(pk=flaw.pk)
        assert after.workflow_state == "DONE"
        assert after.classification_meta == before.classification_meta
        assert after.updated_dt == before.updated_dt

    @pytest.mark.enable_signals
    def test_taskless_flaw_not_classified(self):
        """
        flaws without a Jira task are never classified - relinking their
        affects must not invent a workflow classification (OSIDB-5840)
        """
        ps_update_stream = self._stream()
        flaw = self._flaw(task_key="")
        affect = self._resolved_affect(flaw, ps_update_stream)
        flaw.refresh_from_db()
        assert flaw.workflow_name == ""
        assert flaw.workflow_state == ""

        tracker = self._jira_tracker(flaw, ps_update_stream)
        JiraTrackerDownloadManager.link_tracker_with_affects(tracker.external_system_id)

        flaw.refresh_from_db()
        assert flaw.workflow_name == ""
        assert flaw.workflow_state == ""
        # the link itself still works
        affect.refresh_from_db()
        assert affect.tracker == tracker

    @pytest.mark.enable_signals
    def test_classification_change_schedules_taskman_transition_on_commit(
        self, monkeypatch, django_capture_on_commit_callbacks
    ):
        """
        a workflow state change caused by the relink reclassification must
        schedule the taskman task transition, but only after the transaction
        commits so that no Jira I/O happens under the classification row
        lock (OSIDB-5840)
        """
        ps_update_stream = self._stream()
        flaw = self._flaw()
        self._resolved_affect(flaw, ps_update_stream)
        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"
        tracker = self._jira_tracker(flaw, ps_update_stream)

        monkeypatch.setattr("apps.taskman.constants.JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        # asynchronous taskman so that scheduling is observable without
        # talking to Jira
        monkeypatch.setattr(
            "osidb.models.flaw.flaw.JIRA_TASKMAN_ASYNCHRONOUS_SYNC", True
        )
        transition_schedule = Mock()
        monkeypatch.setattr(JiraTaskTransitionManager, "schedule", transition_schedule)
        sync_schedule = Mock()
        monkeypatch.setattr(JiraTaskSyncManager, "schedule", sync_schedule)

        with django_capture_on_commit_callbacks(execute=False) as callbacks:
            JiraTrackerDownloadManager.link_tracker_with_affects(
                tracker.external_system_id
            )
            # nothing may touch Jira before the transaction commits
            assert not transition_schedule.called

        # exactly one taskman job: a task transition, not a full task re-sync
        assert len(callbacks) == 1
        callbacks[0]()  # simulate the commit

        transition_schedule.assert_called_once_with(str(flaw.uuid))
        assert not sync_schedule.called

    @pytest.mark.enable_signals
    def test_taskman_not_scheduled_when_auto_sync_disabled(
        self, monkeypatch, django_capture_on_commit_callbacks
    ):
        """
        with the taskman auto-sync gate disabled the relink reclassification
        must not schedule any Jira task work (OSIDB-5840)
        """
        ps_update_stream = self._stream()
        flaw = self._flaw()
        self._resolved_affect(flaw, ps_update_stream)
        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"
        tracker = self._jira_tracker(flaw, ps_update_stream)

        monkeypatch.setattr("apps.taskman.constants.JIRA_TASKMAN_AUTO_SYNC_FLAW", False)
        tasksync = Mock()
        monkeypatch.setattr(Flaw, "tasksync", tasksync)

        with django_capture_on_commit_callbacks(execute=True):
            JiraTrackerDownloadManager.link_tracker_with_affects(
                tracker.external_system_id
            )

        # the classification was still persisted...
        flaw.refresh_from_db()
        assert flaw.workflow_state == "DONE"
        # ...but no taskman transition was scheduled at all
        assert not tasksync.called

    @pytest.mark.enable_signals
    def test_taskman_transition_uses_workflow_state_diff(
        self, monkeypatch, django_capture_on_commit_callbacks
    ):
        """
        the scheduled taskman transition must be given the workflow state
        change so that the Jira task is transitioned, not merely re-synced
        (OSIDB-5840)
        """
        ps_update_stream = self._stream()
        flaw = self._flaw()
        self._resolved_affect(flaw, ps_update_stream)
        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"
        tracker = self._jira_tracker(flaw, ps_update_stream)

        monkeypatch.setattr("apps.taskman.constants.JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        tasksync = Mock()
        monkeypatch.setattr(Flaw, "tasksync", tasksync)

        with django_capture_on_commit_callbacks(execute=False) as callbacks:
            JiraTrackerDownloadManager.link_tracker_with_affects(
                tracker.external_system_id
            )
        assert len(callbacks) == 1
        callbacks[0]()  # simulate the commit

        tasksync.assert_called_once_with(
            jira_token=None,
            jira_email=None,
            diff={
                "workflow_state": {
                    "old": "PRE_SECONDARY_ASSESSMENT",
                    "new": "DONE",
                }
            },
        )

    @pytest.mark.enable_signals
    def test_only_the_last_missing_tracker_triggers_the_promotion(
        self, monkeypatch, django_capture_on_commit_callbacks
    ):
        """
        with several affects still missing their trackers only the link of
        the last one changes the classification: the earlier links leave the
        flaw untouched and the promotion - and the single taskman
        transition - happens with the last link (the production scenario
        of OSIDB-5840)
        """
        ps_update_stream = self._stream()
        flaw = self._flaw()
        affect1 = self._resolved_affect(
            flaw, ps_update_stream, ps_component="component-1"
        )
        affect2 = self._resolved_affect(
            flaw, ps_update_stream, ps_component="component-2"
        )
        flaw.refresh_from_db()
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"
        tracker1 = self._jira_tracker(
            flaw, ps_update_stream, ps_component="component-1"
        )
        tracker2 = self._jira_tracker(
            flaw, ps_update_stream, ps_component="component-2"
        )

        monkeypatch.setattr("apps.taskman.constants.JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        tasksync = Mock()
        monkeypatch.setattr(Flaw, "tasksync", tasksync)

        with django_capture_on_commit_callbacks(execute=False) as callbacks:
            # the first link does not change the classification: the second
            # affect is still untracked
            JiraTrackerDownloadManager.link_tracker_with_affects(
                tracker1.external_system_id
            )
            affect1.refresh_from_db()
            assert affect1.tracker == tracker1
            assert (
                Flaw.objects.get(pk=flaw.pk).workflow_state
                == "PRE_SECONDARY_ASSESSMENT"
            )
            assert not tasksync.called

            JiraTrackerDownloadManager.link_tracker_with_affects(
                tracker2.external_system_id
            )

        affect2.refresh_from_db()
        assert affect2.tracker == tracker2
        assert Flaw.objects.get(pk=flaw.pk).workflow_state == "DONE"
        # exactly one taskman transition, triggered by the last link
        assert len(callbacks) == 1
