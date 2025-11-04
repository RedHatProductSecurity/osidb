from time import time

from celery.utils.log import get_task_logger
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import OperationalError, connection
from django.db.models import OuterRef, Q, Subquery
from django.db.models.functions import Cast

from config.celery import app
from osidb.core import set_user_acls
from osidb.mixins import Alert
from osidb.sync_manager import (
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
