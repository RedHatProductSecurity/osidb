import logging
from urllib.parse import urljoin
from xmlrpc.client import ServerProxy

import backoff
import requests
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from requests_gssapi import HTTPSPNEGOAuth

from collectors.framework.models import CollectorMetadata
from osidb.core import set_user_acls
from osidb.dmodels.erratum import Erratum
from osidb.dmodels.tracker import Tracker

from ..utils import BACKOFF_KWARGS, fatal_code
from .constants import (
    ERRATA_TOOL_SERVER,
    ERRATA_TOOL_XMLRPC_BASE_URL,
    PAGE_SIZE,
    RETRYABLE_ERRORS,
)

logger = logging.getLogger(__name__)


@backoff.on_exception(
    backoff.expo, RETRYABLE_ERRORS, giveup=fatal_code, **BACKOFF_KWARGS
)
def get(path, return_json=True, session=None, **request_kwargs):
    """Get the response to a REST API call or raise an exception."""
    url = urljoin(ERRATA_TOOL_SERVER, path)
    if session:
        response = session.get(url, **request_kwargs)
    else:
        response = requests.get(
            url,
            auth=HTTPSPNEGOAuth(),
            timeout=settings.DEFAULT_REQUEST_TIMEOUT,
            **request_kwargs,
        )
    response.raise_for_status()
    return response.json() if return_json else response


def get_erratum(et_id) -> dict:
    """
    get all necessary data for a given erratum

    this is unfortunately one more API query but
    both list and search miss some timestamps
    """
    erratum_json = get(f"/advisory/{et_id}.json")
    erratum = {
        "et_id": et_id,
        "advisory_name": erratum_json["advisory_name"],
        "created_dt": erratum_json["timestamps"]["created_at"],
        "shipped_dt": erratum_json["timestamps"]["actual_ship_date"],
        "updated_dt": erratum_json["timestamps"]["updated_at"],
    }
    logger.info(f"Syncing erratum {erratum['advisory_name'] or erratum['et_id']}")
    logger.debug(
        f"Created: {erratum['created_dt']} "
        f"Updated: {erratum['updated_dt']} "
        f"Shipped: {erratum['shipped_dt']}"
    )
    return erratum


def get_all_errata() -> list[dict]:
    """
    Fetches IDs for all Errata with CVEs when collector is run for first time
    """
    all_errata_with_cves = get("/cve/list.json").keys()
    return [get_erratum(errata_id) for errata_id in all_errata_with_cves]


def get_batch_end() -> timezone.datetime:
    """
    generate end time of the next batch
    never out running tracker collectors
    """
    return min(
        CollectorMetadata.objects.get(
            name="collectors.bzimport.tasks.bztracker_collector"
        ).updated_until_dt,
        CollectorMetadata.objects.get(
            name="collectors.jiraffe.tasks.jira_tracker_collector"
        ).updated_until_dt,
    )


def get_errata_to_sync(updated_after: timezone.datetime) -> list[dict]:
    """
    Fetches IDs for Errata that changed after last collector success time
    """
    query = {"updated_at": updated_after}
    return [get_erratum(erratum["errata_id"]) for erratum in search(query)]


def get_flaws_and_trackers_for_erratum(
    et_id: str,
) -> tuple[set[str], set[str], set[str]]:
    """
    Finds CVEs / flaws, Bugzilla trackers, and Jira trackers fixed in a given erratum.
    Returns a tuple of the CVE / flaw IDs, Bugzilla tracker IDs, and Jira tracker IDs
    /advisory/{id}/bugs.json 	GET 	Fetch the Bugzilla bugs associated with an advisory
    /advisory/{id}/jira_issues.json 	GET 	Fetch the JIRA issues associated with an advisory
    """
    # TODO: Below may need rethinking
    bz_bugs = get(f"/advisory/{et_id}/bugs.json")
    # Bugs with "is_security" = True are flaw bugs. Bugs with "Tracking" keyword are placeholder flaws.
    # Flaw bugs also seem to have non-empty string "alias" and "package" == "vulnerability"
    # Trackers have "is_security" = False, "SecurityTracking" keyword, alias == "", and "package" != "vulnerability"
    flaw_ids = {
        bz_bug["alias"]
        for bz_bug in bz_bugs
        if bz_bug.get("alias") and bz_bug["alias"].startswith("CVE")
    }
    # Don't include placeholder flaws like bz#2073422, which have non-CVE aliases like "java-cpu-2022-04"
    bz_tracker_ids = {
        bz_bug["id"]
        for bz_bug in bz_bugs
        if bz_bug.get("keywords") and "SecurityTracking" in bz_bug["keywords"]
    }

    # The "id_jira" key has the internal Jira ID, but we want the PROJ-1234 key instead
    # The "is_private" key for BZ / Jira trackers seems to be for "private" / internal bugs, not embargoes
    jira_tracker_ids = {
        jira_bug["key"]
        for jira_bug in get(f"/advisory/{et_id}/jira_issues.json")
        if jira_bug.get("labels") and "SecurityTracking" in jira_bug["labels"]
    }
    return flaw_ids, bz_tracker_ids, jira_tracker_ids


def link_bugs_to_errata(erratum_json_list: list[dict]):
    """
    For each erratum ID, find the Bugzilla and Jira bug IDs that are linked to that erratum
    The search API endpoint, to find all errata changed after X time, doesn't return this information
    Then create the Erratum model instance from the ID + name + timestamps, and link the associated bug IDs
    If the bug IDs do not exist, skip linking them. In future we will run bzimport to create them
    """
    # Separate method from above to make testing simpler
    for erratum_json in erratum_json_list:
        flaw_ids, bz_tracker_ids, jira_tracker_ids = get_flaws_and_trackers_for_erratum(
            erratum_json["et_id"]
        )

        # create or update the erratum and its context atomically
        # to prevent any inconsistent intermediate state
        with transaction.atomic():
            erratum = Erratum.objects.create_erratum(**erratum_json)
            erratum.save(auto_timestamps=False)
            # remove the existing erratum-tracker links
            # so only the still existing are preserved
            erratum.trackers.clear()

            for bz_id in bz_tracker_ids:
                try:
                    bz_bug = Tracker.objects.get(
                        external_system_id=bz_id, type=Tracker.TrackerType.BUGZILLA
                    )
                    erratum.trackers.add(bz_bug)
                except Tracker.DoesNotExist:
                    logger.error(f"BZ#{bz_id} does not exist in DB")
            for jira_id in jira_tracker_ids:
                try:
                    jira_issue = Tracker.objects.get(
                        external_system_id=jira_id, type=Tracker.TrackerType.JIRA
                    )
                    erratum.trackers.add(jira_issue)
                except Tracker.DoesNotExist:
                    logger.exception(f"Jira issue {jira_id} does not exist in DB")


@backoff.on_exception(
    backoff.expo, RETRYABLE_ERRORS, giveup=fatal_code, **BACKOFF_KWARGS
)
def search_with_backoff(query, server):
    """Wrapper around the Errata Tool API's search function, to enable backoff and retry for recoverable errors"""
    return server.get_advisory_list(query)


def search(query):
    """Generator that will eventually return all the errata found by the query.

    See ET's documentation /rdoc/ErrataService.html#method-i-get_advisory_list
    """
    query["per_page"] = PAGE_SIZE
    server = ServerProxy(ERRATA_TOOL_XMLRPC_BASE_URL)
    i = 1
    while True:
        query["page"] = i
        data = search_with_backoff(query, server)
        for advisory in data:
            yield advisory

        i += 1
        if not data:
            break


def set_acls_for_et_collector() -> None:
    """Set the ACLs to allow embargo processing, if enabled on server"""
    # celery host is a different host then osidb-service so we need to set osidb.acl independently
    # to be able to CRUD database properly
    # READ_GROUPS and WRITE_GROUPS shouldn't contain overlapping groups
    # i.e. it's safe to add them together without deduplication.
    set_user_acls(settings.ALL_GROUPS)
