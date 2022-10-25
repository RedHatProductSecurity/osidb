import logging
from datetime import datetime
from urllib.parse import urljoin
from xmlrpc.client import ServerProxy

import backoff
import requests
from django.conf import settings
from requests_gssapi import HTTPSPNEGOAuth

from osidb.core import set_user_acls
from osidb.models import Erratum, Tracker

from ..bzimport.constants import BZ_ENABLE_IMPORT_EMBARGOED
from ..utils import BACKOFF_KWARGS, fatal_code
from .constants import PAGE_SIZE, RETRYABLE_ERRORS

logger = logging.getLogger(__name__)


@backoff.on_exception(
    backoff.expo, RETRYABLE_ERRORS, giveup=fatal_code, **BACKOFF_KWARGS
)
def get(path, return_json=True, session=None, **request_kwargs):
    """Get the response to a REST API call or raise an exception."""
    url = urljoin(settings.ERRATA_TOOL_SERVER, path)
    if session:
        response = session.get(url, **request_kwargs)
    else:
        response = requests.get(url, auth=HTTPSPNEGOAuth(), **request_kwargs)
    response.raise_for_status()
    return response.json() if return_json else response


def get_all_errata() -> list[tuple[str, str]]:
    """
    Fetches IDs for all Errata with CVEs when collector is run for first time
    """
    all_errata_with_cves = get("/cve/list.json").items()
    return [
        (errata_id, errata["advisory"]) for errata_id, errata in all_errata_with_cves
    ]


def get_errata_to_sync(updated_after: datetime) -> list[tuple[str, str]]:
    """
    Fetches IDs for Errata that changed after last collector success time
    """
    query = {"updated_at": updated_after}
    return [
        (erratum["errata_id"], erratum["advisory_name"]) for erratum in search(query)
    ]


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


def link_bugs_to_errata(erratum_id_name_pairs: list[tuple[str, str]]):
    """
    For each erratum ID, find the Bugzilla and Jira bug IDs that are linked to that erratum
    The search API endpoint, to find all errata changed after X time, doesn't return this information
    Then create the Erratum model instance from the ID + name, and link the associated bug IDs
    If the bug IDs do not exist, skip linking them. In future we will run bzimport to create them
    """
    # Separate method from above to make testing simpler
    for et_id, advisory_name in erratum_id_name_pairs:
        flaw_ids, bz_tracker_ids, jira_tracker_ids = get_flaws_and_trackers_for_erratum(
            et_id
        )

        if not flaw_ids:
            # No way to avoid fetching data for this erratum
            # But we can avoid storing it unnecessarily
            continue

        erratum, _ = Erratum.objects.update_or_create(
            et_id=et_id, defaults={"advisory_name": advisory_name}
        )

        # TODO: Not enough info here to create a tracker if it doesn't exist
        # Technically we could create the trackers, but they would be missing affects + many other properties
        # So we run the ET collector less frequently than bzimport / Jiraffe, and hope all objects are already created
        # If not, just skip linking that object. Collector refactoring will allow running dependent collectors first
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
    server = ServerProxy(settings.ERRATA_TOOL_XMLRPC_BASE_URL)
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
    groups = settings.PUBLIC_READ_GROUPS + [settings.PUBLIC_WRITE_GROUP]

    # Using embargo groups because ET collector must link errata to possibly-embargoed flaws
    # Note that if an erratum has embargoed flaws / trackers, and below is not set, we will skip linking these
    # The ET collector will not see the embargoed objects in the DB, so assumes they do not exist
    if BZ_ENABLE_IMPORT_EMBARGOED:
        groups += [settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP]

    # celery host is a different host then osidb-service so we need to set osidb.acl independently
    # to be able to CRUD database properly
    # READ_GROUPS and WRITE_GROUPS shouldn't contain overlapping groups
    # i.e. it's safe to add them together without deduplication.
    set_user_acls(groups)
