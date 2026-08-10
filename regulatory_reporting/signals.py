import logging

from django.db import transaction

from osidb.models import Flaw
from regulatory_reporting.models import SRPReport

from .models.upstream import UpstreamNotification
from .services import (
    create_srp_report_milestones,
    is_flaw_upstream_notifiable,
    update_srp_report_milestones,
)

logger = logging.getLogger(__name__)

INCIDENT_STATES_THAT_REQUIRE_SRP_REPORT = [
    Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
    Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
]


def create_srp_report(sender, instance: Flaw, created: bool, **kwargs):
    """
    SIGNAL attached to Flaw model in apps.py when Flaw is saved.
    Auto-create SRP Report and milestones when Flaw is marked as KEV or Major Incident approved.

    Triggers on:
    - EXPLOITS_KEV_APPROVED → Creates report with that reportable_event_type
    - MAJOR_INCIDENT_APPROVED → Creates report with that reportable_event_type

    reportable_event_type matches Flaw.major_incident_state directly.
    Uses Flaw.major_incident_start_dt as the SLA timer start.
    """
    # Skip during fixture loading or migrations
    if kwargs.get("raw"):
        return

    if instance.major_incident_state not in INCIDENT_STATES_THAT_REQUIRE_SRP_REPORT:
        return

    event_type = instance.major_incident_state

    with transaction.atomic():
        srp_report, report_created = SRPReport.objects.get_or_create(
            flaw=instance,
            reportable_event_type=event_type,
            defaults={
                "title": instance.title or f"SRP Report for {instance.uuid}",
                "responsibility_scope": SRPReport.ResponsibilityScope.MANUFACTURER,
                "timer_started_at": instance.major_incident_start_dt,
                "acl_read": instance.acl_read,
                "acl_write": instance.acl_write,
            },
        )

        if not report_created:
            srp_report.title = instance.title or f"SRP Report for {instance.uuid}"
            srp_report.acl_read = instance.acl_read
            srp_report.acl_write = instance.acl_write
            srp_report.timer_started_at = instance.major_incident_start_dt
            srp_report.save()
            update_srp_report_milestones(srp_report)
            logger.info(
                f"Updated SRP Report {srp_report.uuid} for Flaw {instance.uuid} "
            )
        else:
            create_srp_report_milestones(srp_report)
            logger.info(
                f"Created SRP Report {srp_report.uuid} for Flaw {instance.uuid}, "
                f"event type {event_type}"
            )


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
