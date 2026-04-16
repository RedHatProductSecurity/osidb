import json
import subprocess  # nosec: B404
from time import time
from typing import Any

from celery.utils.log import get_task_logger
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.mail.message import EmailMultiAlternatives
from django.db import OperationalError, connection, transaction
from django.db.models import OuterRef, Q, Subquery
from django.db.models.functions import Cast

from config.celery import app
from config.settings import EmailSettings
from osidb.core import set_user_acls
from osidb.helpers import bypass_rls
from osidb.mixins import Alert
from osidb.models import Flaw
from osidb.models.affect import Affect, AffectSettings
from osidb.sync_manager import (
    BZSyncManager,
    JiraTaskSyncManager,
    JiraTaskTransitionManager,
)

logger = get_task_logger(__name__)


def _newcli_include_modules_csv() -> str:
    return ",".join(AffectSettings().auto_create_ps_modules)


def _flaw_components_for_newcli(flaw: Flaw) -> list[str]:
    components = [c for c in (flaw.components or []) if c and str(c).strip()]
    if not components:
        raise ValueError(f"Flaw {flaw.uuid} has no non-empty components for newcli -s")
    return components


def _run_newcli_deps_json(flaw_component: str) -> dict[str, Any]:
    cmd = [
        "newcli",
        "-s",
        flaw_component,
        "--include",
        _newcli_include_modules_csv(),
        "--json",
    ]
    result = subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"newcli failed (exit {result.returncode}): {result.stderr or result.stdout}"
        )
    return json.loads(result.stdout or "{}")


def _sync_affects_from_newcli_deps(
    flaw: Flaw, payload: dict[str, Any]
) -> dict[str, int]:
    deps = payload.get("deps") or []
    created = 0
    skipped = 0
    skipped_existing = 0

    with transaction.atomic():
        for dep in deps:
            if not isinstance(dep, dict):
                skipped += 1
                continue
            ps_update_stream = dep.get("ps_update_stream") or dep.get("ps_module")
            purls = dep.get("purls") or []
            purl_str = purls[0] if purls else None

            if not ps_update_stream or not purl_str:
                logger.warning(
                    "Skipping newcli dep missing ps_update_stream or purls: %s",
                    dep.get("build_nvr"),
                )
                skipped += 1
                continue

            ps_component = Affect(purl=purl_str).ps_component_from_purl()

            if (
                ps_component
                and Affect.objects.filter(
                    flaw=flaw,
                    ps_update_stream=ps_update_stream,
                    ps_component=ps_component,
                ).exists()
            ):
                skipped_existing += 1
                continue

            affect = Affect(
                flaw=flaw,
                ps_update_stream=ps_update_stream,
                purl=purl_str,
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                impact=flaw.impact,
            )
            affect.save(raise_validation_error=False)
            created += 1

    return {
        "created": created,
        "skipped": skipped,
        "skipped_existing": skipped_existing,
    }


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
@bypass_rls
def sync_flaw_affects_from_newcli(flaw_id: str) -> dict[str, Any]:
    """
    For each entry in ``Flaw.components``, run ``newcli`` and create affects for each
    ``deps`` row: ``ps_update_stream`` from the payload, ``purl`` from the first ``purls``
    entry. Existing affects for the same flaw, stream, and ``ps_component`` (inferred from
    the purl) are left unchanged.

    ``newcli --include`` is built from :attr:`osidb.models.affect.AffectSettings.auto_create_ps_modules`
    (``OSIDB_AFFECTS_AUTO_CREATE_PS_MODULES``, JSON list; default ``["hummingbird-1"]``).

    When :attr:`osidb.models.affect.AffectSettings.auto_create` is true
    (``OSIDB_AFFECTS_AUTO_CREATE``), changes to :attr:`~osidb.models.flaw.flaw.Flaw.components`
    register this task on :func:`django.db.transaction.on_commit` from a ``pre_save`` signal
    on :class:`~osidb.models.flaw.flaw.Flaw`.
    """
    flaw = Flaw.objects.get(uuid=flaw_id)
    components = _flaw_components_for_newcli(flaw)
    totals: dict[str, int] = {"created": 0, "skipped": 0, "skipped_existing": 0}
    for flaw_component in components:
        payload = _run_newcli_deps_json(flaw_component)
        stats = _sync_affects_from_newcli_deps(flaw, payload)
        for key in totals:
            totals[key] += stats[key]
    logger.info(
        "sync_flaw_affects_from_newcli flaw=%s components=%s %s",
        flaw_id,
        components,
        totals,
    )
    return totals


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
