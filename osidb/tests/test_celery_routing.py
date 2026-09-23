"""
Tests for Celery queue routing.

These exercise the exact routing pipeline Celery uses at apply_async() time
(app.amqp.router.route) without needing a running broker/worker, so they
work as a red/green check for queue-topology changes: change where a task
is routed and these fail until config/celery.py + the task's `queue=`
default are updated to match.
"""

import pytest
from celery.app.task import extract_exec_options

from config.celery import app

pytestmark = pytest.mark.unit


def _route(task_name, kwargs=None):
    """
    Resolve the queue Celery would actually publish `task_name` to, without
    a broker: reproduces what Task.apply_async() does internally (merge the
    task's own exec options - e.g. its `queue=` default - then run them
    through the configured task_routes router).
    """
    task_obj = app.tasks[task_name]
    preopts = extract_exec_options(task_obj)
    return app.amqp.router.route(preopts, task_name, args=(), kwargs=kwargs or {})


class TestCeleryRouting:
    def test_periodic_collector_tasks_use_low_queue(self):
        """
        Bulk/periodic collector tasks must not share the "high" queue
        with latency-sensitive interactive tasks.
        """
        import collectors.bzimport.tasks  # noqa: F401 ensure task is registered

        options = _route("collectors.bzimport.tasks.bztracker_collector")
        assert options["queue"].name == "low"

    @pytest.mark.parametrize(
        "task_name",
        [
            "sync_manager.jira_task_sync",
            "sync_manager.jira_task_transition",
            "sync_manager.jira_tracker_download",
        ],
    )
    def test_high_priority_sync_manager_tasks_use_high_queue(self, task_name):
        """
        High-priority, latency-sensitive tasks (Jira sync/transition/download)
        stay on "high" queue so they aren't queued behind long-running
        collector imports on "low" queue.
        """
        options = _route(task_name)
        assert options["queue"].name == "high"

    @pytest.mark.parametrize(
        "task_name",
        [
            "sync_manager.bzsync",
            "sync_manager.bz_tracker_download",
        ],
    )
    def test_low_priority_sync_manager_tasks_use_low_queue(self, task_name):
        """
        Lower-priority sync tasks (BZ sync/download) use "low" queue.
        """
        options = _route(task_name)
        assert options["queue"].name == "low"

    def test_ace_task_uses_high_queue(self):
        """
        ACE affect creation (sync_flaw_affects_from_newcli) is event-driven
        and latency-sensitive, so it must route to "high" queue.
        """
        import apps.ace.tasks  # noqa: F401 ensure task is registered

        options = _route("apps.ace.tasks.sync_flaw_affects_from_newcli")
        assert options["queue"].name == "high"

    def test_async_send_email_uses_high_queue(self):
        """
        Email sending is event-driven and must route to "high" queue.
        """
        options = _route("osidb.tasks.async_send_email")
        assert options["queue"].name == "high"

    @pytest.mark.parametrize(
        "task_name",
        [
            "osidb.tasks.check_for_non_periodic_reschedules",
            "osidb.tasks.stale_alert_cleanup",
            "osidb.tasks.refresh_affect_v1_view",
        ],
    )
    def test_housekeeping_tasks_use_low_queue(self, task_name):
        """
        Beat-scheduled housekeeping tasks (reschedule checks, stale alert
        cleanup, materialized view refresh) use "low" queue so they don't
        compete with latency-sensitive tasks on "high" queue.
        """
        options = _route(task_name)
        assert options["queue"].name == "low"
