import logging

from .models.upstream import UpstreamNotification
from .services import (
    is_flaw_upstream_notifiable,
)

logger = logging.getLogger(__name__)


def check_upstream_notifiable(sender, instance, **kwargs):
    """
    On Flaw save, check criteria for upstream maintainer notification.
    """
    if not is_flaw_upstream_notifiable(instance):
        return

    notification, created = UpstreamNotification.objects.get_or_create(
        flaw=instance,
        upstream_project=None,
        defaults={
            "status": UpstreamNotification.NotificationStatus.REQUIRED,
            "reportability_reason": UpstreamNotification.ReportabilityReason.RED_HAT_IDENTIFIED,
            "acl_read": instance.acl_read,
            "acl_write": instance.acl_write,
        },
    )
    if created:
        logger.info(
            f"Created upstream notification {notification.uuid} for flaw {instance.uuid}"
        )


def link_mapping_to_notification(sender, instance, created, **kwargs):
    """
    On FlawUpstreamMapping creation, backfill the existing project
    """
    if not created:
        return

    notification = (
        UpstreamNotification.objects.filter(
            flaw=instance.flaw, upstream_project__isnull=True
        )
        .order_by("created_dt")
        .first()
    )

    if notification:
        notification.upstream_project = instance.upstream_project
        notification.save(update_fields=["upstream_project", "updated_dt"])
        logger.info(
            f"Backfilled upstream_project on notification {notification.uuid} "
            f"for {instance.flaw.uuid}"
        )
    else:
        notification = UpstreamNotification.objects.create(
            flaw=instance.flaw,
            upstream_project=instance.upstream_project,
            status=UpstreamNotification.NotificationStatus.REQUIRED,
            reportability_reason=UpstreamNotification.ReportabilityReason.RED_HAT_IDENTIFIED,
            acl_read=instance.flaw.acl_read,
            acl_write=instance.flaw.acl_write,
        )
        logger.info(
            f"Created new notification {notification.uuid} for {instance.flaw.uuid}"
        )
