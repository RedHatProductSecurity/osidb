"""
Errata Tool collector
"""
from celery.schedules import crontab
from celery.utils.log import get_task_logger

from collectors.framework.models import collector
from osidb.models.erratum import Erratum

from .constants import ERRATA_COLLECTOR_ENABLED, ERRATA_TOOL_SERVER
from .core import (
    get_all_errata,
    get_batch_end,
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
        "collectors.jiraffe.tasks.jira_tracker_collector",
    ],
    enabled=ERRATA_COLLECTOR_ENABLED,
)
def errata_collector(collector_obj) -> str:
    """Errata Tool collector"""

    logger.info(f"Fetching Errata from '{ERRATA_TOOL_SERVER}'")
    set_acls_for_et_collector()
    # we have to make sure that we never out run
    # tracker collectors not to miss any linkage
    #
    # even though it means that we will fetch some errata
    # multiple times as ET does not provide a way to fetch
    # batch between two times - only after or before one
    batch_end = get_batch_end()

    if not collector_obj.is_complete:
        # Fetch all Errata that have CVEs from Errata Tool, since collector has never run.
        # This endpoint doesn't support searching for only errata updated after some date.
        erratum_json_list = get_all_errata()
    else:
        # Fetch all errata changed after last collector start time, even errata with no CVEs we don't care about.
        # This endpoint doesn't support searching for only errata with CVEs, non-None security impact, etc.
        erratum_json_list = get_errata_to_sync(collector_obj.metadata.updated_until_dt)

    errata_tool_collector(collector_obj, erratum_json_list, batch_end)
    return (
        f"Collector {collector_obj.name} finished with {len(erratum_json_list)} "
        f"errata synced and is updated until {batch_end}."
    )


def errata_tool_collector(collector_obj, erratum_json_list, batch_end) -> None:
    """Common code for initial and periodic Errata Tool collector sync
    For each erratum ID, find the Bugzilla and Jira bug IDs
    (separately, because above API endpoints don't return this information)
    Then create the Erratum model instance from the ID + name + timestamps, and link the associated bug IDs
    If some bug ID doesn't exist, just skip linking it. In future we will run bzimport to create it
    """
    logger.info(f"Fetched {len(erratum_json_list)} Errata, going to sync.")
    link_bugs_to_errata(erratum_json_list)

    collector_obj.store(complete=True, updated_until_dt=batch_end)
    logger.info("Errata sync was successful.")
