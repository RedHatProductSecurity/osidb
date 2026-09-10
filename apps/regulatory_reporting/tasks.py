import logging

from django.conf import settings
from django.utils import timezone

from config.celery import app
from osidb.core import set_user_acls

from .models.upstream import UpstreamNotification

logger = logging.getLogger(__name__)


@app.task
def mark_upstream_notification_sent(result, notification_uuid):
    """
    Success callback once async_send_email completes successfully.
    """
    set_user_acls(settings.ALL_GROUPS)
    updated = UpstreamNotification.objects.filter(
        uuid=notification_uuid,
        status=UpstreamNotification.NotificationStatus.QUEUED,
    ).update(
        status=UpstreamNotification.NotificationStatus.SENT,
        last_error="",
        sent_at=timezone.now(),
    )
    if updated:
        logger.info("Upstream maintainer notification %s sent", notification_uuid)


@app.task
def mark_upstream_notification_failed(request, exc, traceback, notification_uuid):
    """
    Failure callback that records the error if async_send_email raises.
    """
    set_user_acls(settings.ALL_GROUPS)
    updated = UpstreamNotification.objects.filter(
        uuid=notification_uuid,
        status=UpstreamNotification.NotificationStatus.QUEUED,
    ).update(
        status=UpstreamNotification.NotificationStatus.FAILED,
        last_error=str(exc),
    )
    if updated:
        logger.error(
            "Upstream maintainer notification %s failed to send: %s",
            notification_uuid,
            type(exc).__name__,
        )
