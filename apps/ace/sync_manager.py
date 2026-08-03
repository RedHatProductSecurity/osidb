from celery.utils.log import get_task_logger
from django.conf import settings

from config.celery import app
from osidb.core import set_user_acls
from osidb.sync_manager import SyncManager

logger = get_task_logger(__name__)


class AffectAutomationSyncManager(SyncManager):
    """
    Sync manager for delegating affect creation to the external
    Affect Automation microservice.

    sync_id is the Flaw UUID.
    """

    class Meta:
        proxy = True

    @staticmethod
    @app.task(name="sync_manager.affect_automation", bind=True)
    def sync_task(task, flaw_id, **kwargs):
        from apps.ace.microservice import dispatch_to_microservice

        AffectAutomationSyncManager.started(flaw_id, task)
        set_user_acls(settings.ALL_GROUPS)

        try:
            dispatch_to_microservice(flaw_id)
        except Exception as e:
            AffectAutomationSyncManager.failed(flaw_id, e)
        else:
            AffectAutomationSyncManager.finished(flaw_id)
