from time import time

from celery.utils.log import get_task_logger
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.mail.message import EmailMultiAlternatives
from django.db import OperationalError, connection, transaction
from django.db.models import F, OuterRef, Q, Subquery
from django.db.models.functions import Cast

from config.celery import app
from config.settings import EmailSettings
from osidb.core import set_user_acls
from osidb.mixins import Alert
from osidb.models import Affect, Tracker
from osidb.sync_manager import (
    ACLHistorySyncManager,
    BZSyncManager,
    JiraTaskSyncManager,
    JiraTaskTransitionManager,
)

logger = get_task_logger(__name__)


@app.task
def check_for_non_periodic_reschedules():
    """
    some sync managers perform async jobs based on non-periodic
    tasks like user requests so the accompanied reschedule
    is not guaranteed to be triggered with any period and
    therefore we check for reschedules periodically here
    """
    set_user_acls(settings.ALL_GROUPS)

    BZSyncManager.check_for_reschedules()
    JiraTaskSyncManager.check_for_reschedules()
    JiraTaskTransitionManager.check_for_reschedules()


@app.task
def stale_alert_cleanup():
    """Delete stale alerts from the database.

    On every run, this collector will check if the alert is still valid by comparing
    the creation time of the alert with the validation time of the Model.

    If the creation time of the alert is older than the validation time of the Model,
    the alert is considered stale and will be deleted.
    """
    set_user_acls(settings.ALL_GROUPS)

    content_types = ContentType.objects.filter(
        id__in=Alert.objects.values_list("content_type", flat=True).distinct()
    )

    logger.info(f"Searching for stale alerts in {content_types.count()} content types")

    query = Q()

    for content_type in content_types:
        model_class = content_type.model_class()

        if not model_class:
            logger.error(f"Model class not found for content type {content_type}")
            continue

        subquery = Subquery(
            model_class.objects.filter(
                pk=Cast(OuterRef("object_id"), output_field=model_class._meta.pk)
            )
            .order_by("last_validated_dt")
            .values("last_validated_dt")[:1]
        )

        query |= Q(
            content_type=content_type,
            created_dt__lt=subquery,
        )

    filtered_queryset = Alert.objects.filter(query)

    if filtered_queryset.count() == 0:
        return "No Stale Alerts Found"

    logger.info(f"Found {filtered_queryset.count()} stale alerts")

    deleted_alerts_count = filtered_queryset.delete()[0]

    logger.info(f"Deleted {deleted_alerts_count} stale alerts")

    return f"Deleted {deleted_alerts_count} Stale Alerts"


@app.task
def refresh_affect_v1_view():
    """Refresh the materialized view for affects v1."""
    set_user_acls(settings.ALL_GROUPS)

    start_time = time()
    sql = "REFRESH MATERIALIZED VIEW CONCURRENTLY affect_v1;"
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql)

        elapsed = time() - start_time
        message = f'Successfully refreshed "affect_v1" in {elapsed:.2f} seconds.'
        logger.info(message)
        return message
    except OperationalError as e:
        # This is expected if another refresh is already in progress, which is a possible scenario
        # with concurrent refresh. Just log it and exit gracefully.
        message = f'Could not refresh "affect_v1" (likely already in progress): {e}'
        logger.warning(message)
        return message


@app.task
def async_send_email(**kwargs) -> int:
    if not EmailSettings().send_enabled:
        return 0
    html_body = kwargs.pop("html_body", False)
    try:
        email_message = EmailMultiAlternatives(**kwargs)
        email_message.attach_alternative(html_body, "text/html")
        result = email_message.send()
        logger.info(f"Email sent successfully to {email_message.to}")
        return result
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        raise


@app.task
def fix_acl_inconsistencies():
    """
    Fix ACL inconsistencies for Affects and Trackers.

    - For Affects: Update ACLs to match their parent Flaw
    - For Trackers: Update ACLs to match related Flaws only if all Flaws have identical ACLs
    """
    set_user_acls(settings.ALL_GROUPS)

    affects_fixed = 0
    trackers_fixed = 0
    trackers_skipped = 0

    # Filter Affects mismatching ACLs from their Flaws
    affects_to_fix = Affect.objects.exclude(
        Q(acl_read=F("flaw__acl_read")) & Q(acl_write=F("flaw__acl_write"))
    ).select_related("flaw")

    for affect in affects_to_fix:
        if affect.flaw:
            with transaction.atomic():
                # Update ACLs to match the parent Flaw
                affect.acl_read = affect.flaw.acl_read
                affect.acl_write = affect.flaw.acl_write
                affect.save(raise_validation_error=False, auto_timestamps=False)
                ACLHistorySyncManager.schedule(affect)
                affects_fixed += 1

    logger.info(f"Fixed ACL inconsistencies for {affects_fixed} Affects")

    # Fix Trackers where all related Flaws have identical ACLs
    trackers_to_check = (
        Tracker.objects.filter(
            affects__isnull=False  # exclude orphaned trackers
        )
        .filter(  # exclude trackers that matches it's flaw ACLs
            ~Q(acl_read=F("affects__flaw__acl_read"))
            | ~Q(acl_write=F("affects__flaw__acl_write"))
        )
        .distinct()
        .prefetch_related("affects__flaw")
    )

    for tracker in trackers_to_check:
        # Get all distinct ACL combinations for flaws related to this tracker
        flaw_acls = (
            tracker.affects.filter(flaw__isnull=False)
            .values("flaw__acl_read", "flaw__acl_write")
            .distinct()
        )

        if not flaw_acls.exists():
            continue

        # Check if all flaws have identical ACLs (only 1 distinct combination)
        if flaw_acls.count() == 1:
            with transaction.atomic():
                # All flaws have the same ACLs, get the first one
                flaw_acl = flaw_acls.first()
                tracker.acl_read = flaw_acl["flaw__acl_read"]
                tracker.acl_write = flaw_acl["flaw__acl_write"]
                tracker.save(raise_validation_error=False, auto_timestamps=False)
                ACLHistorySyncManager.schedule(tracker)
                trackers_fixed += 1
        else:
            # Flaws have different ACLs, skip this tracker
            trackers_skipped += 1

    logger.info(
        f"Fixed ACL inconsistencies for {trackers_fixed} Trackers, "
        f"skipped {trackers_skipped} Trackers with differing Flaw ACLs"
    )

    return {
        "affects_fixed": affects_fixed,
        "trackers_fixed": trackers_fixed,
        "trackers_skipped": trackers_skipped,
    }
