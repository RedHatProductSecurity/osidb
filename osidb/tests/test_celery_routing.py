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
    def test_periodic_collector_tasks_use_collectors_queue(self):
        """
        Bulk/periodic collector tasks must not share the "default" queue
        with latency-sensitive interactive tasks.
        """
        import collectors.bzimport.tasks  # noqa: F401 ensure task is registered

        options = _route("collectors.bzimport.tasks.bztracker_collector")
        assert options["queue"].name == "collectors"

    @pytest.mark.parametrize(
        "task_name",
        [
            "sync_manager.jira_task_sync",
            "sync_manager.jira_task_transition",
            "sync_manager.bzsync",
        ],
    )
    def test_interactive_sync_manager_tasks_use_default_queue(self, task_name):
        """
        Interactive, per-object sync tasks stay on "default" so they aren't
        queued behind long-running collector imports.
        """
        options = _route(task_name)
        assert options["queue"].name == "default"
