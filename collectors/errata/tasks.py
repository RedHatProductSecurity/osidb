"""
Errata Tool collector
"""
from celery.schedules import crontab
from celery.utils.log import get_task_logger
from django.conf import settings
from django.utils import timezone

from collectors.framework.models import collector
from osidb.models import Erratum

from .core import (
    get_all_errata,
    get_errata_to_sync,
    link_bugs_to_errata,
    set_acls_for_et_collector,
)

logger = get_task_logger(__name__)


@collector(
    # execute this every 5 minutes
    crontab=crontab(minute="*/5"),
    data_models=[Erratum],
    depends_on=[
        "collectors.bzimport.tasks.bztracker_collector",
        # TODO Jiraffe is not a collector but should be
        # "collectors.jiraffe.tasks.jiraffe_collector",
    ],
)
def errata_collector(collector_obj) -> str:
    """Errata Tool collector"""

    logger.info(f"Fetching Errata from '{settings.ERRATA_TOOL_SERVER}'")
    start_time = timezone.now()
    set_acls_for_et_collector()

    if not collector_obj.is_complete:
        # Fetch all Errata that have CVEs from Errata Tool, since collector has never run.
        # This endpoint doesn't support searching for only errata updated after some date.
        erratum_id_name_pairs = get_all_errata()
    else:
        # Fetch all errata changed after last collector start time, even errata with no CVEs we don't care about.
        # This endpoint doesn't support searching for only errata with CVEs, non-None security impact, etc.
        erratum_id_name_pairs = get_errata_to_sync(
            collector_obj.metadata.updated_until_dt
        )

    errata_tool_collector(collector_obj, erratum_id_name_pairs, start_time)
    return (
        f"Collector {collector_obj.name} finished with {len(erratum_id_name_pairs)} "
        f"errata synced and is updated until {start_time}."
    )


def errata_tool_collector(collector_obj, erratum_id_name_pairs, start_time) -> None:
    """Common code for initial and periodic Errata Tool collector sync
    For each erratum ID, find the Bugzilla and Jira bug IDs
    (separately, because above API endpoints don't return this information)
    Then create the Erratum model instance from the ID + name, and link the associated bug IDs
    If some bug ID doesn't exist, just skip linking it. In future we will run bzimport to create it
    """
    logger.info(f"Fetched {len(erratum_id_name_pairs)} Errata, going to sync.")
    link_bugs_to_errata(erratum_id_name_pairs)

    collector_obj.store(complete=True, updated_until_dt=start_time)
    logger.info("Errata sync was successful.")
