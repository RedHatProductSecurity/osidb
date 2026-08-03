"""Tests for apps.ace.sync_manager."""

from unittest.mock import MagicMock, patch

import pytest

from apps.ace.sync_manager import AffectAutomationSyncManager
from osidb.sync_manager import SyncManager
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


class TestAffectAutomationSyncManager:
    def test_is_proxy_model(self):
        assert AffectAutomationSyncManager._meta.proxy is True

    def test_inherits_sync_manager(self):
        assert issubclass(AffectAutomationSyncManager, SyncManager)

    def test_schedule_creates_sync_manager_row(self):
        flaw = FlawFactory(components=["urllib3"])
        flaw_id = str(flaw.uuid)

        AffectAutomationSyncManager.schedule(flaw_id)

        assert SyncManager.objects.filter(
            name="AffectAutomationSyncManager", sync_id=flaw_id
        ).exists()

    @patch("apps.ace.microservice.dispatch_to_microservice")
    def test_sync_task_calls_dispatch(self, mock_dispatch):
        flaw = FlawFactory(components=["urllib3"])
        flaw_id = str(flaw.uuid)

        SyncManager.objects.create(
            name="AffectAutomationSyncManager",
            sync_id=flaw_id,
        )

        mock_dispatch.return_value = {
            "created": 1,
            "skipped_existing": 0,
            "affects": [],
        }
        mock_task = MagicMock()
        mock_task.request.id = "test-task-id"

        AffectAutomationSyncManager.sync_task(mock_task, flaw_id)

        mock_dispatch.assert_called_once_with(flaw_id)

        manager = SyncManager.objects.get(
            name="AffectAutomationSyncManager", sync_id=flaw_id
        )
        assert manager.last_finished_dt is not None

    @patch("apps.ace.microservice.dispatch_to_microservice")
    def test_sync_task_records_failure(self, mock_dispatch):
        flaw = FlawFactory(components=["urllib3"])
        flaw_id = str(flaw.uuid)

        SyncManager.objects.create(
            name="AffectAutomationSyncManager",
            sync_id=flaw_id,
        )

        mock_dispatch.side_effect = ConnectionError("service unavailable")
        mock_task = MagicMock()
        mock_task.request.id = "test-task-id"

        with pytest.raises(ConnectionError):
            AffectAutomationSyncManager.sync_task(mock_task, flaw_id)

        manager = SyncManager.objects.get(
            name="AffectAutomationSyncManager", sync_id=flaw_id
        )
        assert manager.last_failed_dt is not None
        assert manager.last_consecutive_failures == 1


class TestSignalRouting:
    @patch("apps.ace.sync_manager.AffectAutomationSyncManager.schedule")
    def test_microservice_backend_routes_to_sync_manager(
        self, mock_schedule, monkeypatch
    ):
        monkeypatch.setenv("OSIDB_AFFECTS_AUTO_CREATE", "true")
        monkeypatch.setenv("OSIDB_AFFECTS_AUTO_CREATE_BACKEND", "microservice")

        flaw = FlawFactory.build(components=["urllib3"])
        flaw.save()

        mock_schedule.assert_called_once_with(str(flaw.uuid))

    @patch("apps.ace.tasks.sync_flaw_affects_from_newcli.delay")
    def test_in_process_backend_routes_to_celery_task(self, mock_delay, monkeypatch):
        monkeypatch.setenv("OSIDB_AFFECTS_AUTO_CREATE", "true")
        monkeypatch.setenv("OSIDB_AFFECTS_AUTO_CREATE_BACKEND", "in_process")

        flaw = FlawFactory.build(components=["urllib3"])
        flaw.save()

        mock_delay.assert_called_once_with(str(flaw.uuid))

    def test_auto_create_disabled_skips_both(self, monkeypatch):
        monkeypatch.setenv("OSIDB_AFFECTS_AUTO_CREATE", "false")

        with (
            patch(
                "apps.ace.sync_manager.AffectAutomationSyncManager.schedule"
            ) as mock_schedule,
            patch("apps.ace.tasks.sync_flaw_affects_from_newcli.delay") as mock_delay,
        ):
            FlawFactory.build(components=["urllib3"]).save()

            mock_schedule.assert_not_called()
            mock_delay.assert_not_called()
