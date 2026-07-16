from django.conf import settings

from config.celery import app
from osidb.core import set_user_acls

from .models.upstream import UpstreamNotification


@app.task
def mark_upstream_notification_sent(result, notification_uuid):
    """
    Success callback once async_send_email completes successfully.
    """
    set_user_acls(settings.ALL_GROUPS)
    UpstreamNotification.objects.filter(uuid=notification_uuid).update(
        status=UpstreamNotification.NotificationStatus.SENT,
        last_error="",
    )


@app.task
def mark_upstream_notification_failed(request, exc, traceback, notification_uuid):
    """
    Failure callback that records the error if async_send_email raises.
    """
    set_user_acls(settings.ALL_GROUPS)
    UpstreamNotification.objects.filter(uuid=notification_uuid).update(
        status=UpstreamNotification.NotificationStatus.FAILED,
        last_error=str(exc),
    )
