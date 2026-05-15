from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from celery.exceptions import Ignore
from django.test import TestCase
from freezegun import freeze_time

from osidb.models.affect import Affect
from osidb.models.tracker import Tracker
from osidb.sync_manager import (
    BZTrackerDownloadManager,
    JiraTaskDownloadManager,
    JiraTaskSyncManager,
    JiraTaskTransitionManager,
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


class TestSyncManagerFailed(TestCase):
    """Test cases for SyncManager.failed() method with reraise parameter"""

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_with_reraise_true_raises_exception(self):
        """Test that failed() with reraise=True (default) raises the exception"""
        flaw = FlawFactory(embargoed=False)

        SyncManager.objects.create(name=SyncManager.__name__, sync_id=flaw.uuid)

        test_exception = RuntimeError("Test error")

        with pytest.raises(RuntimeError, match="Test error"):
            SyncManager.failed(flaw.uuid, test_exception, reraise=True)

        # Verify the failure was recorded even though it was raised
        manager = SyncManager.objects.get(name=SyncManager.__name__, sync_id=flaw.uuid)
        assert manager.last_failed_reason == "Test error"
        assert manager.last_failed_dt is not None

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_with_reraise_false_does_not_raise(self):
        """Test that failed() with reraise=False does not raise the exception"""
        flaw = FlawFactory(embargoed=False)

        SyncManager.objects.create(name=SyncManager.__name__, sync_id=flaw.uuid)

        test_exception = RuntimeError("Test error")

        # Should not raise
        SyncManager.failed(flaw.uuid, test_exception, reraise=False)

        # Verify the failure was recorded
        manager = SyncManager.objects.get(name=SyncManager.__name__, sync_id=flaw.uuid)
        assert manager.last_failed_reason == "Test error"
        assert manager.last_failed_dt is not None
        assert manager.last_consecutive_failures == 1

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_default_reraise_raises_exception(self):
        """Test that failed() without reraise parameter (default) raises the exception"""
        flaw = FlawFactory(embargoed=False)

        SyncManager.objects.create(name=SyncManager.__name__, sync_id=flaw.uuid)

        test_exception = ValueError("Default behavior")

        with pytest.raises(ValueError, match="Default behavior"):
            SyncManager.failed(flaw.uuid, test_exception)

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_records_error_reason(self):
        """Test that failed() records the exception message"""
        flaw = FlawFactory(embargoed=False)

        SyncManager.objects.create(name=SyncManager.__name__, sync_id=flaw.uuid)

        test_exception = RuntimeError("Connection timeout")

        SyncManager.failed(flaw.uuid, test_exception, reraise=False)

        # Verify the failure was recorded with correct reason
        manager = SyncManager.objects.get(name=SyncManager.__name__, sync_id=flaw.uuid)
        assert manager.last_failed_reason == "Connection timeout"
        assert manager.last_failed_dt is not None

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_permanent_sets_flag(self):
        """Test that permanent failures set the permanently_failed flag"""
        flaw = FlawFactory(embargoed=False)

        SyncManager.objects.create(name=SyncManager.__name__, sync_id=flaw.uuid)

        test_exception = RuntimeError("Data not found")

        SyncManager.failed(flaw.uuid, test_exception, permanent=True, reraise=False)

        # Verify permanent flag is set
        manager = SyncManager.objects.get(name=SyncManager.__name__, sync_id=flaw.uuid)
        assert manager.permanently_failed is True
        assert manager.last_failed_reason == "Data not found"

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_updates_consecutive_failures(self):
        """Test that consecutive failures counter is incremented"""
        flaw = FlawFactory(embargoed=False)

        manager = SyncManager.objects.create(
            name=SyncManager.__name__,
            sync_id=flaw.uuid,
            last_consecutive_failures=2,
        )

        SyncManager.failed(flaw.uuid, RuntimeError("Test"), reraise=False)

        manager.refresh_from_db()
        assert manager.last_consecutive_failures == 3
        assert manager.last_consecutive_reschedules == 0  # Should be reset

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_becomes_permanent_after_max_failures(self):
        """Test that sync becomes permanently failed when already at max consecutive failures"""
        flaw = FlawFactory(embargoed=False)

        # Set to the threshold (MAX_CONSECUTIVE_FAILURES is 5)
        # The code checks the current value before incrementing, so at 5 it becomes permanent
        manager = SyncManager.objects.create(
            name=SyncManager.__name__,
            sync_id=flaw.uuid,
            last_consecutive_failures=5,
        )

        SyncManager.failed(flaw.uuid, RuntimeError("Final failure"), reraise=False)

        manager.refresh_from_db()
        assert manager.last_consecutive_failures == 6
        # Verify it becomes permanent when at or above threshold
        assert manager.permanently_failed is True

    @freeze_time(datetime(2025, 6, 24))
    def test_failed_with_multiline_exception_message(self):
        """Test that exception messages are stripped of extra whitespace"""
        flaw = FlawFactory(embargoed=False)

        SyncManager.objects.create(name=SyncManager.__name__, sync_id=flaw.uuid)

        test_exception = RuntimeError("  Error with whitespace\n\n  ")

        SyncManager.failed(flaw.uuid, test_exception, reraise=False)

        manager = SyncManager.objects.get(name=SyncManager.__name__, sync_id=flaw.uuid)
        assert manager.last_failed_reason == "Error with whitespace"


class TestBZTrackerDownloadManagerFailed(TestCase):
    """Test cases for BZTrackerDownloadManager.failed() with reraise=False"""

    def setUp(self):
        """Set up test data with Bugzilla-compatible ps_module"""
        # Create a ps_module with bugzilla BTS
        self.ps_module = PsModuleFactory(bts_name="bugzilla")
        self.ps_update_stream = PsUpdateStreamFactory(ps_module=self.ps_module)

    @freeze_time(datetime(2025, 6, 24))
    def test_missing_flaws_failure_does_not_reraise(self):
        """Test that missing flaws error doesn't reraise exception"""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_module=self.ps_module.name,
            ps_update_stream=self.ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        tracker = TrackerFactory(
            affects=[affect],
            ps_update_stream=affect.ps_update_stream,
            type=Tracker.TrackerType.BUGZILLA,
        )

        BZTrackerDownloadManager.objects.create(
            name=BZTrackerDownloadManager.__name__,
            sync_id=tracker.external_system_id,
        )

        test_exception = RuntimeError(
            "Flaws do not exist: uuid-1, uuid-2, Affects do not exist: uuid-3"
        )

        # This should not raise an exception
        BZTrackerDownloadManager.failed(
            tracker.external_system_id,
            test_exception,
            reraise=False,
        )

        # Verify the failure was recorded
        manager = BZTrackerDownloadManager.objects.get(
            name=BZTrackerDownloadManager.__name__,
            sync_id=tracker.external_system_id,
        )
        # This is a temporary failure, not permanent (matches sync_task line 622)
        assert manager.permanently_failed is False
        assert "Flaws do not exist" in manager.last_failed_reason

    @freeze_time(datetime(2025, 6, 24))
    def test_missing_affects_failure_does_not_reraise(self):
        """Test that missing affects error doesn't reraise exception"""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_module=self.ps_module.name,
            ps_update_stream=self.ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        tracker = TrackerFactory(
            affects=[affect],
            ps_update_stream=affect.ps_update_stream,
            type=Tracker.TrackerType.BUGZILLA,
        )

        BZTrackerDownloadManager.objects.create(
            name=BZTrackerDownloadManager.__name__,
            sync_id=tracker.external_system_id,
        )

        test_exception = RuntimeError("Affects do not exist: uuid-1, uuid-2")

        BZTrackerDownloadManager.failed(
            tracker.external_system_id,
            test_exception,
            permanent=True,
            reraise=False,
        )

        # Verify the failure was recorded
        manager = BZTrackerDownloadManager.objects.get(
            name=BZTrackerDownloadManager.__name__,
            sync_id=tracker.external_system_id,
        )
        assert manager.permanently_failed is True
        assert "Affects do not exist" in manager.last_failed_reason

    @freeze_time(datetime(2025, 6, 24))
    def test_no_affects_found_failure_does_not_reraise(self):
        """Test that 'no affects found' error doesn't reraise exception"""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_module=self.ps_module.name,
            ps_update_stream=self.ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        tracker = TrackerFactory(
            affects=[affect],
            ps_update_stream=affect.ps_update_stream,
            type=Tracker.TrackerType.BUGZILLA,
        )

        BZTrackerDownloadManager.objects.create(
            name=BZTrackerDownloadManager.__name__,
            sync_id=tracker.external_system_id,
        )

        test_exception = RuntimeError("No Affects found")

        BZTrackerDownloadManager.failed(
            tracker.external_system_id, test_exception, reraise=False
        )

        # Verify the failure was recorded
        manager = BZTrackerDownloadManager.objects.get(
            name=BZTrackerDownloadManager.__name__,
            sync_id=tracker.external_system_id,
        )
        # This should be temporary failure, not permanent
        assert manager.permanently_failed is False
        assert "No Affects found" in manager.last_failed_reason

    @freeze_time(datetime(2025, 6, 24))
    def test_unexpected_error_still_reraises_by_default(self):
        """Test that unexpected errors still reraise when reraise is not specified"""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_module=self.ps_module.name,
            ps_update_stream=self.ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        tracker = TrackerFactory(
            affects=[affect],
            ps_update_stream=affect.ps_update_stream,
            type=Tracker.TrackerType.BUGZILLA,
        )

        BZTrackerDownloadManager.objects.create(
            name=BZTrackerDownloadManager.__name__,
            sync_id=tracker.external_system_id,
        )

        test_exception = ValueError("Unexpected error")

        # Unexpected errors should still raise when reraise is default (True)
        with pytest.raises(ValueError, match="Unexpected error"):
            BZTrackerDownloadManager.failed(
                tracker.external_system_id,
                test_exception,
                # Note: reraise defaults to True
            )

    @freeze_time(datetime(2025, 6, 24))
    def test_reraise_false_does_not_raise(self):
        """Test that reraise=False prevents exceptions from being raised"""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_module=self.ps_module.name,
            ps_update_stream=self.ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        tracker = TrackerFactory(
            affects=[affect],
            ps_update_stream=affect.ps_update_stream,
            type=Tracker.TrackerType.BUGZILLA,
        )

        BZTrackerDownloadManager.objects.create(
            name=BZTrackerDownloadManager.__name__,
            sync_id=tracker.external_system_id,
        )

        test_exception = RuntimeError("No Affects found")

        # Call failed() with reraise=False - should not raise
        BZTrackerDownloadManager.failed(
            tracker.external_system_id, test_exception, reraise=False
        )

        # Verify the failure was recorded
        manager = BZTrackerDownloadManager.objects.get(
            name=BZTrackerDownloadManager.__name__,
            sync_id=tracker.external_system_id,
        )
        assert manager.last_failed_reason == "No Affects found"
